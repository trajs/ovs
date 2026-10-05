/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "esp-ctl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

#include "byte-order.h"
#include "esp.h"
#include "hash.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "random.h"
#include "smap.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(esp_ctl);

/* A security association installed by the IKE daemon.
 *
 * An inbound SA is in the SAD as long as it exists.  Several can exist for
 * one tunnel while it is rekeyed.  Received packets get the interface ID as
 * their tunnel ID, which binds them to the tunnel with that 'esp_if_id'.
 *
 * An outbound SA is in the SAD under the interface ID and the peer's
 * address, which is what the tunnel's datapath flows look up.  A new
 * outbound SA for the same tunnel, installed when the SAs are rekeyed,
 * replaces the previous one there, so that the flows do not change.  The
 * previous one then remains until the IKE daemon deletes it. */
struct ike_sa {
    struct hmap_node node;      /* In 'ike_sas'. */
    bool inbound;
    ovs_be32 spi;
    struct in6_addr src, dst;
    uint32_t if_id;
    bool encap;                 /* ESP in UDP, as negotiated. */
    struct esp_sa *sa;
};

static struct hmap ike_sas = HMAP_INITIALIZER(&ike_sas);

/* SPIs returned by "esp/spi-alloc" and not yet used by an inbound SA. */
#define MAX_RESERVED_SPIS 1024
static struct hmap reserved_spis = HMAP_INITIALIZER(&reserved_spis);
struct reserved_spi {
    struct hmap_node node;
    ovs_be32 spi;
};

static uint32_t
ike_sa_hash(bool inbound, ovs_be32 spi, const struct in6_addr *dst)
{
    return hash_bytes(dst, sizeof *dst,
                      hash_2words((OVS_FORCE uint32_t) spi, inbound));
}

static struct ike_sa *
ike_sa_find(bool inbound, ovs_be32 spi, const struct in6_addr *dst)
{
    struct ike_sa *ike;

    HMAP_FOR_EACH_WITH_HASH (ike, node, ike_sa_hash(inbound, spi, dst),
                             &ike_sas) {
        if (ike->inbound == inbound && ike->spi == spi
            && ipv6_addr_equals(&ike->dst, dst)) {
            return ike;
        }
    }
    return NULL;
}

static struct ike_sa *
ike_sa_find_by_esp_sa(const struct esp_sa *sa)
{
    struct ike_sa *ike;

    HMAP_FOR_EACH (ike, node, &ike_sas) {
        if (ike->sa == sa) {
            return ike;
        }
    }
    return NULL;
}

static struct reserved_spi *
reserved_spi_find(ovs_be32 spi)
{
    struct reserved_spi *r;

    HMAP_FOR_EACH_WITH_HASH (r, node, hash_int((OVS_FORCE uint32_t) spi, 0),
                             &reserved_spis) {
        if (r->spi == spi) {
            return r;
        }
    }
    return NULL;
}

static void
reserved_spi_release(ovs_be32 spi)
{
    struct reserved_spi *r = reserved_spi_find(spi);

    if (r) {
        hmap_remove(&reserved_spis, &r->node);
        free(r);
    }
}

static bool
parse_addr(const char *s, struct in6_addr *addr)
{
    ovs_be32 ip4;

    if (s && inet_pton(AF_INET, s, &ip4) == 1) {
        in6_addr_set_mapped_ipv4(addr, ip4);
        return true;
    }
    return s && inet_pton(AF_INET6, s, addr) == 1;
}

static bool
parse_u32(const char *s, uint32_t min, uint32_t *value)
{
    unsigned long long int x;
    char *tail;

    if (!s) {
        return false;
    }
    errno = 0;
    x = strtoull(s, &tail, 0);
    if (errno || *tail || tail == s || x < min || x > UINT32_MAX) {
        return false;
    }
    *value = x;
    return true;
}

/* Parses "key=value" arguments into 'args'. */
static char *
parse_args(int argc, const char *argv[], struct smap *args)
{
    for (int i = 1; i < argc; i++) {
        const char *eq = strchr(argv[i], '=');

        if (!eq) {
            return xasprintf("argument '%s' is not key=value", argv[i]);
        }
        smap_replace_nocopy(args, xmemdup0(argv[i], eq - argv[i]),
                            xstrdup(eq + 1));
    }
    return NULL;
}

/* Parses the arguments that identify an SA: "dir", "spi" and "dst". */
static char *
parse_sa_id(const struct smap *args, bool *inbound, ovs_be32 *spi,
            struct in6_addr *dst)
{
    const char *dir = smap_get(args, "dir");
    uint32_t spi_;

    if (!dir || (strcmp(dir, "in") && strcmp(dir, "out"))) {
        return xstrdup("'dir' must be 'in' or 'out'");
    }
    *inbound = !strcmp(dir, "in");
    if (!parse_u32(smap_get(args, "spi"), 256, &spi_)) {
        return xstrdup("'spi' must be between 256 and 4294967295");
    }
    *spi = htonl(spi_);
    if (!parse_addr(smap_get(args, "dst"), dst)) {
        return xstrdup("'dst' must be an IP address");
    }
    return NULL;
}

/* "esp/spi-alloc": returns an SPI that no inbound SA uses. */
static void
esp_ctl_spi_alloc(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct reserved_spi *r;
    char reply[16];
    ovs_be32 spi;

    if (hmap_count(&reserved_spis) >= MAX_RESERVED_SPIS) {
        /* Allocated, but never used.  Forget them. */
        HMAP_FOR_EACH_POP (r, node, &reserved_spis) {
            free(r);
        }
    }

    /* Like the Linux kernel, use the range 0xc0000000 to 0xcfffffff. */
    do {
        spi = htonl(0xc0000000 | (random_uint32() & 0x0fffffff));
    } while (esp_sad_lookup(spi, &in6addr_any) || reserved_spi_find(spi));

    r = xmalloc(sizeof *r);
    r->spi = spi;
    hmap_insert(&reserved_spis, &r->node, hash_int((OVS_FORCE uint32_t) spi,
                                                   0));

    snprintf(reply, sizeof reply, "0x%08"PRIx32, ntohl(spi));
    unixctl_command_reply(conn, reply);
}

/* "esp/sa-add dir=in|out spi=SPI src=IP dst=IP if_id=ID key=KEY [esn=yes]
 *              [replay=N] [encap=yes]" */
static void
esp_ctl_sa_add(struct unixctl_conn *conn, int argc, const char *argv[],
               void *aux OVS_UNUSED)
{
    struct smap args = SMAP_INITIALIZER(&args);
    struct esp_sa_params params;
    struct in6_addr src, dst;
    struct esp_sa *sa, *old;
    struct ike_sa *ike;
    uint32_t if_id;
    bool inbound;
    char *error;
    ovs_be32 spi;

    memset(&params, 0, sizeof params);

    error = parse_args(argc, argv, &args);
    if (!error) {
        error = parse_sa_id(&args, &inbound, &spi, &dst);
    }
    if (error) {
        goto out;
    }
    if (!parse_addr(smap_get(&args, "src"), &src)) {
        error = xstrdup("'src' must be an IP address");
        goto out;
    }
    if (!parse_u32(smap_get(&args, "if_id"), 1, &if_id)) {
        error = xstrdup("'if_id' must be between 1 and 4294967295");
        goto out;
    }
    error = esp_parse_key(smap_get_def(&args, "key", ""), &params);
    if (error) {
        goto out;
    }
    if (ike_sa_find(inbound, spi, &dst)) {
        error = xstrdup("SA already exists");
        goto out;
    }

    params.spi = spi;
    params.esn = smap_get_bool(&args, "esn", false);
    if (inbound) {
        params.sad_id = spi;
        params.tun_id = htonll(if_id);
        params.replay_window = smap_get_uint(&args, "replay",
                                             ESP_DEFAULT_REPLAY_WINDOW);
        if (esp_sad_lookup(spi, &in6addr_any)) {
            error = xstrdup("SPI already in use");
            goto out;
        }
    } else {
        params.sad_id = htonl(if_id);
        params.dst = dst;
    }

    sa = esp_sa_create(&params);
    if (!sa) {
        error = xstrdup("invalid parameters (replay window?)");
        goto out;
    }

    old = esp_sad_lookup(params.sad_id, &params.dst);
    if (!old) {
        ovs_assert(!esp_sad_insert(sa));
    } else if (!inbound && ike_sa_find_by_esp_sa(old)) {
        /* Rekeying: the new outbound SA takes over. */
        esp_sad_replace(old, sa);
    } else {
        /* A manually keyed tunnel uses this SPI or interface ID. */
        esp_sa_destroy(sa);
        error = xstrdup("conflicts with a manually keyed esp tunnel");
        goto out;
    }

    ike = xzalloc(sizeof *ike);
    ike->inbound = inbound;
    ike->spi = spi;
    ike->src = src;
    ike->dst = dst;
    ike->if_id = if_id;
    ike->encap = smap_get_bool(&args, "encap", false);
    ike->sa = sa;
    hmap_insert(&ike_sas, &ike->node, ike_sa_hash(inbound, spi, &dst));
    if (inbound) {
        reserved_spi_release(spi);
    }
    VLOG_INFO("added %s SA spi 0x%08"PRIx32" for if_id %"PRIu32,
              inbound ? "inbound" : "outbound", ntohl(spi), if_id);

out:
    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
    } else {
        unixctl_command_reply(conn, NULL);
    }
    memset(&params, 0, sizeof params);
    smap_destroy(&args);
}

static void
ike_sa_delete(struct ike_sa *ike)
{
    const struct esp_sa_params *p = esp_sa_get_params(ike->sa);

    /* An outbound SA that was replaced by a newer one is no longer in the
     * SAD. */
    if (esp_sad_lookup(p->sad_id, &p->dst) == ike->sa) {
        esp_sad_remove(ike->sa);
    }
    esp_sa_destroy_postponed(ike->sa);
    hmap_remove(&ike_sas, &ike->node);
    free(ike);
}

/* "esp/sa-del dir=in|out spi=SPI dst=IP" */
static void
esp_ctl_sa_del(struct unixctl_conn *conn, int argc, const char *argv[],
               void *aux OVS_UNUSED)
{
    struct smap args = SMAP_INITIALIZER(&args);
    struct in6_addr dst;
    struct ike_sa *ike;
    bool inbound;
    char *error;
    ovs_be32 spi;

    error = parse_args(argc, argv, &args);
    if (!error) {
        error = parse_sa_id(&args, &inbound, &spi, &dst);
    }
    if (!error) {
        ike = ike_sa_find(inbound, spi, &dst);
        if (ike) {
            VLOG_INFO("deleted %s SA spi 0x%08"PRIx32" for if_id %"PRIu32,
                      inbound ? "inbound" : "outbound", ntohl(spi),
                      ike->if_id);
            ike_sa_delete(ike);
        } else {
            error = xstrdup("no such SA");
        }
    }

    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
    } else {
        unixctl_command_reply(conn, NULL);
    }
    smap_destroy(&args);
}

/* "esp/sa-query dir=in|out spi=SPI dst=IP": replies with the number of
 * packets and bytes processed by the SA, "packets=N bytes=N". */
static void
esp_ctl_sa_query(struct unixctl_conn *conn, int argc, const char *argv[],
                 void *aux OVS_UNUSED)
{
    struct smap args = SMAP_INITIALIZER(&args);
    struct in6_addr dst;
    struct ike_sa *ike;
    bool inbound;
    char *error;
    ovs_be32 spi;

    error = parse_args(argc, argv, &args);
    if (!error) {
        error = parse_sa_id(&args, &inbound, &spi, &dst);
    }
    if (!error) {
        ike = ike_sa_find(inbound, spi, &dst);
        if (ike) {
            struct esp_sa_stats stats;
            char *reply;

            esp_sa_get_stats(ike->sa, &stats);
            reply = xasprintf("packets=%"PRIu64" bytes=%"PRIu64,
                              stats.n_packets, stats.n_bytes);
            unixctl_command_reply(conn, reply);
            free(reply);
        } else {
            error = xstrdup("no such SA");
        }
    }

    if (error) {
        unixctl_command_reply_error(conn, error);
        free(error);
    }
    smap_destroy(&args);
}

/* "esp/sa-flush": deletes all the SAs installed through "esp/sa-add". */
static void
esp_ctl_sa_flush(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ike_sa *ike;

    HMAP_FOR_EACH_SAFE (ike, node, &ike_sas) {
        ike_sa_delete(ike);
    }
    unixctl_command_reply(conn, NULL);
}

static int
compare_ike_sas(const void *a_, const void *b_)
{
    const struct ike_sa *const *a = a_;
    const struct ike_sa *const *b = b_;

    if ((*a)->inbound != (*b)->inbound) {
        return (*a)->inbound ? 1 : -1;
    }
    return ntohl((*a)->spi) < ntohl((*b)->spi) ? -1
           : ntohl((*a)->spi) > ntohl((*b)->spi);
}

/* Appends to 'ds' the SAs installed for interface ID 'if_id', outbound ones
 * first, by SPI.  An outbound SA that was replaced by a newer one is marked
 * "standby". */
void
esp_ctl_format(struct ds *ds, uint32_t if_id)
{
    struct ike_sa **sas = xmalloc(hmap_count(&ike_sas) * sizeof *sas);
    struct ike_sa *ike;
    size_t n = 0;

    HMAP_FOR_EACH (ike, node, &ike_sas) {
        if (ike->if_id == if_id) {
            sas[n++] = ike;
        }
    }
    qsort(sas, n, sizeof *sas, compare_ike_sas);

    for (size_t i = 0; i < n; i++) {
        const struct esp_sa_params *p = esp_sa_get_params(sas[i]->sa);
        bool active = esp_sad_lookup(p->sad_id, &p->dst) == sas[i]->sa;

        esp_sa_format(ds, (sas[i]->inbound ? "inbound "
                           : active ? "outbound" : "outbound (standby)"),
                      sas[i]->sa, sas[i]->inbound);
    }
    free(sas);
}

void
esp_ctl_init(void)
{
    unixctl_command_register("esp/spi-alloc", "", 0, 0,
                             esp_ctl_spi_alloc, NULL);
    unixctl_command_register_sensitive(
        "esp/sa-add", "dir=in|out spi=SPI src=IP dst=IP if_id=ID key=KEY "
        "[esn=yes] [replay=N] [encap=yes]", 6, 9, esp_ctl_sa_add, NULL);
    unixctl_command_register("esp/sa-del", "dir=in|out spi=SPI dst=IP",
                             3, 3, esp_ctl_sa_del, NULL);
    unixctl_command_register("esp/sa-query", "dir=in|out spi=SPI dst=IP",
                             3, 3, esp_ctl_sa_query, NULL);
    unixctl_command_register("esp/sa-flush", "", 0, 0,
                             esp_ctl_sa_flush, NULL);
}
