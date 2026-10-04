/*
 * Copyright (c) 2026 Nicira, Inc.
 *
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

#include "conntrack-log.h"

#include <netinet/in.h>

#include "coverage.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "packets.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(conntrack_log);

COVERAGE_DEFINE(conntrack_log_dropped);
COVERAGE_DEFINE(conntrack_log_ratelimited);

/* Per-thread ring size; must be a power of two.  Each slot is 120 bytes, so a
 * ring takes about 2 MB.  A ring is allocated the first time a thread logs an
 * event, and there can be at most CT_LOG_MAX_RINGS of them. */
#define CT_LOG_RING_SIZE 16384
#define CT_LOG_RING_MASK (CT_LOG_RING_SIZE - 1)
BUILD_ASSERT_DECL(IS_POW2(CT_LOG_RING_SIZE));
#define CT_LOG_MAX_RINGS 128

#define CT_LOG_DRAIN_INTERVAL_MS 10

/* Events are emitted in timestamp order.  Since they come from several rings,
 * an event is held back this long after its timestamp, to give events with
 * an earlier timestamp that are still in flight (e.g. the NEW event of a very
 * short-lived connection, whose DESTROY was logged by another thread) time to
 * show up. */
#define CT_LOG_HOLD_MS 20

struct ct_log_event {
    long long ts_msec;          /* Wall clock time of the event. */
    long long age_msec;         /* Time since creation (DESTROY only). */
    struct conn_key orig;
    struct conn_key reply;
    uint32_t mark;
    uint16_t nat_action;
    uint8_t type;               /* enum ct_log_event_type. */
    uint8_t reason;             /* enum ct_log_reason. */
};

/* Single-producer, single-consumer ring.  Each logging thread owns one ring
 * (as its only producer) and the 'ct_log' thread is the only consumer of all
 * of them, so no atomic read-modify-write is needed and there is no
 * contention between producers. */
struct ct_log_ring {
    PADDED_MEMBERS(CACHE_LINE_SIZE, atomic_uint32_t tail;);  /* Producer. */
    PADDED_MEMBERS(CACHE_LINE_SIZE, atomic_uint32_t head;);  /* Consumer. */
    atomic_bool in_use;            /* Owned by a live thread. */
    struct ct_log_event slots[CT_LOG_RING_SIZE];
};

atomic_uint conntrack_log_mask = ATOMIC_VAR_INIT(0);
atomic_bool conntrack_log_all_zones = ATOMIC_VAR_INIT(true);
atomic_uint32_t conntrack_log_zones[CT_LOG_ZONE_WORDS];

static atomic_uint ct_log_rate = ATOMIC_VAR_INIT(1000);  /* Events/sec. */
static struct ovsthread_once ct_log_once = OVSTHREAD_ONCE_INITIALIZER;

/* Registry of rings.  Rings are never freed: a ring whose thread has exited
 * is drained and then reused by the next thread that needs one. */
static struct ovs_mutex ct_log_mutex = OVS_MUTEX_INITIALIZER;
static struct ct_log_ring *ct_log_rings[CT_LOG_MAX_RINGS];
static atomic_uint ct_log_n_rings;
static ovsthread_key_t ct_log_key;

static void *ct_log_thread_main(void *);
static void ct_log_unixctl_set(struct unixctl_conn *, int, const char *[],
                               void *);
static void ct_log_unixctl_show(struct unixctl_conn *, int, const char *[],
                                void *);

void
conntrack_log_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        unixctl_command_register("conntrack/log-set",
                                 "[events=new,destroy|all|none] [zones=all|LIST] "
                                 "[rate=N]", 0, 3, ct_log_unixctl_set, NULL);
        unixctl_command_register("conntrack/log-show", "", 0, 0,
                                 ct_log_unixctl_show, NULL);
        ovsthread_once_done(&once);
    }
}

static void
ct_log_ring_release(void *ring_)
{
    struct ct_log_ring *ring = ring_;

    atomic_store_explicit(&ring->in_use, false, memory_order_release);
}

/* Returns the calling thread's ring, claiming a free one or allocating a new
 * one the first time.  Returns NULL if all CT_LOG_MAX_RINGS are in use. */
static struct ct_log_ring *
ct_log_thread_ring(void)
{
    struct ct_log_ring *ring = ovsthread_getspecific(ct_log_key);
    unsigned int n;

    if (OVS_LIKELY(ring)) {
        return ring;
    }

    ovs_mutex_lock(&ct_log_mutex);
    atomic_read_relaxed(&ct_log_n_rings, &n);
    for (unsigned int i = 0; i < n && !ring; i++) {
        bool expected = false;

        if (atomic_compare_exchange_strong_explicit(
                &ct_log_rings[i]->in_use, &expected, true,
                memory_order_acquire, memory_order_relaxed)) {
            ring = ct_log_rings[i];
        }
    }
    if (!ring && n < CT_LOG_MAX_RINGS) {
        ring = xmalloc_cacheline(sizeof *ring);
        atomic_init(&ring->tail, 0);
        atomic_init(&ring->head, 0);
        atomic_init(&ring->in_use, true);
        ct_log_rings[n] = ring;
        atomic_store_explicit(&ct_log_n_rings, n + 1, memory_order_release);
    }
    ovs_mutex_unlock(&ct_log_mutex);

    if (ring) {
        ovsthread_setspecific(ct_log_key, ring);
    }
    return ring;
}

static bool
ct_log_ring_push(struct ct_log_ring *ring, const struct ct_log_event *ev)
{
    uint32_t tail, head;

    atomic_read_relaxed(&ring->tail, &tail);
    atomic_read_explicit(&ring->head, &head, memory_order_acquire);
    if (tail - head >= CT_LOG_RING_SIZE) {
        return false;                           /* Full. */
    }

    ring->slots[tail & CT_LOG_RING_MASK] = *ev;
    atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);
    return true;
}

void
conntrack_log_conn(enum ct_log_event_type type, enum ct_log_reason reason,
                   struct conn *conn)
{
    struct ct_log_ring *ring = ct_log_thread_ring();
    struct ct_log_event ev;

    if (OVS_UNLIKELY(!ring)) {
        COVERAGE_INC(conntrack_log_dropped);
        return;
    }

    /* Timestamps are taken here, on the producer side, so that they are
     * not skewed by the delay before the 'ct_log' thread gets to the event. */
    ev.ts_msec = time_wall_msec();
    ev.age_msec = type == CT_LOG_DESTROY ? time_msec() - conn->created : 0;
    ev.orig = conn->key_node[CT_DIR_FWD].key;
    ev.reply = conn->key_node[CT_DIR_REV].key;
    ev.nat_action = conn->nat_action;
    ev.type = type;
    ev.reason = reason;

    ovs_mutex_lock(&conn->lock);
    ev.mark = conn->mark;
    ovs_mutex_unlock(&conn->lock);

    if (!ct_log_ring_push(ring, &ev)) {
        COVERAGE_INC(conntrack_log_dropped);
    }
}

static void
ct_log_format_endpoint(struct ds *ds, const struct conn_key *key,
                       const struct ct_endpoint *ep)
{
    bool v6 = key->dl_type == htons(ETH_TYPE_IPV6);

    if (v6) {
        ds_put_char(ds, '[');
        ipv6_format_addr(&ep->addr.ipv6, ds);
        ds_put_char(ds, ']');
    } else {
        ds_put_format(ds, IP_FMT, IP_ARGS(ep->addr.ipv4));
    }

    if (key->nw_proto == IPPROTO_ICMP || key->nw_proto == IPPROTO_ICMPV6) {
        ds_put_format(ds, "(id=%"PRIu16",type=%"PRIu8",code=%"PRIu8")",
                      ntohs(ep->icmp_id), ep->icmp_type, ep->icmp_code);
    } else {
        ds_put_format(ds, ":%"PRIu16, ntohs(ep->port));
    }
}

static void
ct_log_format_tuple(struct ds *ds, const char *name,
                    const struct conn_key *key)
{
    ds_put_format(ds, " %s=", name);
    ct_log_format_endpoint(ds, key, &key->src);
    ds_put_cstr(ds, "->");
    ct_log_format_endpoint(ds, key, &key->dst);
}

static const char *
ct_log_reason_name(enum ct_log_reason reason)
{
    switch (reason) {
    case CT_LOG_R_EXPIRED:
        return "expired";
    case CT_LOG_R_FLUSHED:
        return "flushed";
    case CT_LOG_R_NONE:
    case CT_LOG_R_SHUTDOWN:
    default:
        return "unknown";
    }
}

static void
ct_log_format_event(struct ds *ds, const struct ct_log_event *ev)
{
    ds_put_format(ds, "%s ts=%lld", ev->type == CT_LOG_NEW ? "NEW" : "DESTROY",
                  ev->ts_msec);

    switch (ev->orig.nw_proto) {
    case IPPROTO_TCP:
        ds_put_cstr(ds, " proto=tcp");
        break;
    case IPPROTO_UDP:
        ds_put_cstr(ds, " proto=udp");
        break;
    case IPPROTO_ICMP:
        ds_put_cstr(ds, " proto=icmp");
        break;
    case IPPROTO_ICMPV6:
        ds_put_cstr(ds, " proto=icmpv6");
        break;
    default:
        ds_put_format(ds, " proto=%"PRIu8, ev->orig.nw_proto);
    }
    ds_put_format(ds, " zone=%"PRIu16, ev->orig.zone);
    ct_log_format_tuple(ds, "orig", &ev->orig);
    ct_log_format_tuple(ds, "reply", &ev->reply);

    if (ev->nat_action) {
        ds_put_format(ds, " nat=%s%s%s",
                      ev->nat_action & NAT_ACTION_SNAT_ALL ? "snat" : "",
                      (ev->nat_action & NAT_ACTION_SNAT_ALL)
                      && (ev->nat_action & NAT_ACTION_DNAT_ALL) ? "," : "",
                      ev->nat_action & NAT_ACTION_DNAT_ALL ? "dnat" : "");
    }
    if (ev->mark) {
        ds_put_format(ds, " mark=%#"PRIx32, ev->mark);
    }
    if (ev->type == CT_LOG_DESTROY) {
        ds_put_format(ds, " created=%lld age=%lldms reason=%s",
                      ev->ts_msec - ev->age_msec, ev->age_msec,
                      ct_log_reason_name(ev->reason));
    }
}

static int
ct_log_event_compare(const void *a_, const void *b_)
{
    const struct ct_log_event *a = a_, *b = b_;

    if (a->ts_msec != b->ts_msec) {
        return a->ts_msec < b->ts_msec ? -1 : 1;
    }
    return (int) a->type - (int) b->type;     /* NEW before DESTROY. */
}

/* Moves all the events currently in the rings to '*pending'. */
static void
ct_log_collect(struct ct_log_event **pending, size_t *n, size_t *allocated)
{
    unsigned int n_rings;

    atomic_read_explicit(&ct_log_n_rings, &n_rings, memory_order_acquire);
    for (unsigned int i = 0; i < n_rings; i++) {
        struct ct_log_ring *ring = ct_log_rings[i];
        uint32_t head, tail;

        atomic_read_relaxed(&ring->head, &head);
        atomic_read_explicit(&ring->tail, &tail, memory_order_acquire);
        if (head == tail) {
            continue;
        }
        if (*n + (tail - head) > *allocated) {
            *allocated = MAX(*allocated * 2, *n + (tail - head));
            *pending = xrealloc(*pending, *allocated * sizeof **pending);
        }
        for (; head != tail; head++) {
            (*pending)[(*n)++] = ring->slots[head & CT_LOG_RING_MASK];
        }
        atomic_store_explicit(&ring->head, head, memory_order_release);
    }
}

/* Collects the events of all the rings, sorts them by timestamp, then formats
 * and logs the ones old enough to be safely ordered, at most 'rate' per second
 * (0 means unlimited); events over the budget are dropped and counted. */
static void *
ct_log_thread_main(void *aux OVS_UNUSED)
{
    struct ct_log_event *pending = NULL;
    size_t n_pending = 0, allocated = 0;
    long long window_start = 0;
    unsigned int budget = 0;
    struct ds ds = DS_EMPTY_INITIALIZER;

    for (;;) {
        long long now = time_msec();
        unsigned int rate;
        size_t done = 0;

        atomic_read_relaxed(&ct_log_rate, &rate);
        if (now - window_start >= 1000) {
            window_start = now;
            budget = rate;
        }

        ct_log_collect(&pending, &n_pending, &allocated);
        qsort(pending, n_pending, sizeof *pending, ct_log_event_compare);

        long long watermark = time_wall_msec() - CT_LOG_HOLD_MS;
        for (; done < n_pending && pending[done].ts_msec <= watermark;
             done++) {
            if (rate && !budget) {
                COVERAGE_INC(conntrack_log_ratelimited);
                continue;
            }
            budget -= rate ? 1 : 0;

            ds_clear(&ds);
            ct_log_format_event(&ds, &pending[done]);
            VLOG_INFO("%s", ds_cstr(&ds));
        }
        n_pending -= done;
        memmove(pending, pending + done, n_pending * sizeof *pending);

        poll_timer_wait(CT_LOG_DRAIN_INTERVAL_MS);
        poll_block();
    }

    OVS_NOT_REACHED();
}

/* Enables the drain thread on first use. */
static void
ct_log_start(void)
{
    if (ovsthread_once_start(&ct_log_once)) {
        ovsthread_key_create(&ct_log_key, ct_log_ring_release);
        ovs_thread_create("ct_log", ct_log_thread_main, NULL);
        ovsthread_once_done(&ct_log_once);
    }
}

static unsigned int
ct_log_get_rate(void)
{
    unsigned int rate;

    atomic_read_relaxed(&ct_log_rate, &rate);
    return rate;
}

void
conntrack_log_set(unsigned int mask, unsigned int rate)
{
    atomic_store_relaxed(&ct_log_rate, rate);
    if (mask) {
        ct_log_start();
    }
    /* Release: pairs with the acquire in conntrack_log_enabled(), so a
     * producer that sees the mask also sees the thread key. */
    atomic_store_explicit(&conntrack_log_mask, mask, memory_order_release);
}

static bool
ct_log_parse_events(const char *s, unsigned int *mask)
{
    char *copy = xstrdup(s), *save = NULL, *tok;
    bool ok = true;

    *mask = 0;
    for (tok = strtok_r(copy, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (!strcmp(tok, "new")) {
            *mask |= CT_LOG_NEW;
        } else if (!strcmp(tok, "destroy")) {
            *mask |= CT_LOG_DESTROY;
        } else if (!strcmp(tok, "all")) {
            *mask |= CT_LOG_ALL_EVENTS;
        } else if (strcmp(tok, "none")) {
            ok = false;
        }
    }
    free(copy);
    return ok;
}

/* Parses a zone list such as "all" or "1,5,10-20" into 'words'.  Returns
 * false if 'spec' is invalid; '*all' is set if it was "all". */
static bool
ct_log_parse_zones(const char *spec, uint32_t words[CT_LOG_ZONE_WORDS],
                   bool *all)
{
    char *copy = xstrdup(spec), *save = NULL, *tok;
    bool ok = true;

    *all = false;
    memset(words, 0, CT_LOG_ZONE_WORDS * sizeof *words);
    for (tok = strtok_r(copy, ",", &save); tok && ok;
         tok = strtok_r(NULL, ",", &save)) {
        unsigned int lo, hi;
        int n;

        if (!strcmp(tok, "all")) {
            *all = true;
        } else if (ovs_scan(tok, "%u-%u%n", &lo, &hi, &n) && !tok[n]
                   && lo <= hi && hi <= UINT16_MAX) {
            for (unsigned int z = lo; z <= hi; z++) {
                words[z / 32] |= UINT32_C(1) << (z % 32);
            }
        } else if (str_to_uint(tok, 10, &lo) && lo <= UINT16_MAX) {
            words[lo / 32] |= UINT32_C(1) << (lo % 32);
        } else {
            ok = false;
        }
    }
    free(copy);
    return ok;
}

static void
ct_log_set_zones(const uint32_t words[CT_LOG_ZONE_WORDS], bool all)
{
    /* Write the bitmap before dropping "all", and raise "all" first, so that
     * a concurrent producer never sees a filter that is neither the old nor
     * the new one for a zone that is in both. */
    if (all) {
        atomic_store_relaxed(&conntrack_log_all_zones, true);
        return;
    }
    for (int i = 0; i < CT_LOG_ZONE_WORDS; i++) {
        atomic_store_relaxed(&conntrack_log_zones[i], words[i]);
    }
    atomic_store_explicit(&conntrack_log_all_zones, false,
                          memory_order_release);
}

static void
ct_log_format_zones(struct ds *ds)
{
    bool all;
    int start = -1;

    atomic_read_relaxed(&conntrack_log_all_zones, &all);
    if (all) {
        ds_put_cstr(ds, "all");
        return;
    }

    for (int z = 0; z <= UINT16_MAX + 1; z++) {
        bool set = false;

        if (z <= UINT16_MAX) {
            uint32_t word;

            atomic_read_relaxed(&conntrack_log_zones[z / 32], &word);
            set = word & (UINT32_C(1) << (z % 32));
        }
        if (set && start < 0) {
            start = z;
        } else if (!set && start >= 0) {
            ds_put_format(ds, "%s%d", ds->length && ds_last(ds) != ' '
                          ? "," : "", start);
            if (z - 1 != start) {
                ds_put_format(ds, "-%d", z - 1);
            }
            start = -1;
        }
    }
    if (ds_last(ds) == ' ') {
        ds_put_cstr(ds, "none");
    }
}

static void
ct_log_unixctl_set(struct unixctl_conn *conn, int argc, const char *argv[],
                   void *aux OVS_UNUSED)
{
    unsigned int new_mask, rate;
    bool have_mask = false, have_rate = false, have_zones = false;
    uint32_t *zone_words = NULL;
    bool all_zones = false;

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "events=", 7)) {
            if (!ct_log_parse_events(argv[i] + 7, &new_mask)) {
                unixctl_command_reply_error(conn, "invalid events list");
                return;
            }
            have_mask = true;
        } else if (!strncmp(argv[i], "rate=", 5)) {
            if (!str_to_uint(argv[i] + 5, 10, &rate)) {
                unixctl_command_reply_error(conn, "invalid rate");
                return;
            }
            have_rate = true;
        } else if (!strncmp(argv[i], "zones=", 6)) {
            if (!zone_words) {
                zone_words = xmalloc(CT_LOG_ZONE_WORDS * sizeof *zone_words);
            }
            if (!ct_log_parse_zones(argv[i] + 6, zone_words, &all_zones)) {
                free(zone_words);
                unixctl_command_reply_error(conn, "invalid zones list");
                return;
            }
            have_zones = true;
        } else {
            free(zone_words);
            unixctl_command_reply_error(conn, "unknown argument");
            return;
        }
    }

    if (have_zones) {
        ct_log_set_zones(zone_words, all_zones);
    }
    free(zone_words);

    if (have_rate) {
        atomic_store_relaxed(&ct_log_rate, rate);
    }
    if (have_mask) {
        conntrack_log_set(new_mask, ct_log_get_rate());
    }
    unixctl_command_reply(conn, NULL);
}

static void
ct_log_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    unsigned int mask, rate;

    atomic_read_relaxed(&conntrack_log_mask, &mask);
    atomic_read_relaxed(&ct_log_rate, &rate);

    ds_put_format(&ds, "events: %s%s%s%s\n",
                  mask & CT_LOG_NEW ? "new" : "",
                  mask == CT_LOG_ALL_EVENTS ? " " : "",
                  mask & CT_LOG_DESTROY ? "destroy" : "",
                  mask ? "" : "none");
    ds_put_cstr(&ds, "zones: ");
    ct_log_format_zones(&ds);
    ds_put_char(&ds, '\n');
    ds_put_format(&ds, "rate limit: %u events/sec%s\n", rate,
                  rate ? "" : " (unlimited)");
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}
