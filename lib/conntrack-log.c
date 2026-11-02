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
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "packets.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(conntrack_log);

/* The only way a line is ever skipped: the per-second output budget is
 * spent.  There is no ring to overflow any more, so there is no separate
 * "dropped" counter -- this one covers every skipped line. */
COVERAGE_DEFINE(conntrack_log_ratelimited);

atomic_bool conntrack_log_enabled_flag = false;
atomic_bool conntrack_log_all_zones = true;
atomic_uint32_t conntrack_log_zones[CT_LOG_ZONE_WORDS];

static atomic_uint ct_log_rate = 1000;  /* Lines/sec. */

/* A plain per-second token bucket, shared by however many threads call
 * conntrack_log_conn() -- in practice, the 'ct_clean' sweep thread almost
 * always, and occasionally whatever thread handles an explicit flush.
 * Neither is a PMD, both are rare and slow-moving next to a packet rate, so
 * there is no dedicated lock here: a window reset racing with a budget
 * decrement can let through or hold back at most one extra line right at a
 * second boundary, which is not worth a mutex to avoid. */
static atomic_llong ct_log_window_start = 0;
static atomic_int ct_log_budget = 0;

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
                                 "[enable|disable] [zones=all|LIST] "
                                 "[rate=N]", 0, 3, ct_log_unixctl_set, NULL);
        unixctl_command_register("conntrack/log-show", "", 0, 0,
                                 ct_log_unixctl_show, NULL);
        ovsthread_once_done(&once);
    }
}

/* Returns true if a line may be written right now, having spent one unit of
 * the per-second budget; false if the caller must skip it (and count it as
 * rate-limited).  Only ever gates whether a line is WRITTEN -- callers must
 * not let it gate whether the connection is removed. */
static bool
ct_log_take_budget(long long now)
{
    unsigned int rate;
    long long window_start;
    int budget_before;

    atomic_read_relaxed(&ct_log_rate, &rate);
    if (!rate) {
        return true;                             /* Unlimited. */
    }

    atomic_read_relaxed(&ct_log_window_start, &window_start);
    if (now - window_start >= 1000) {
        atomic_store_relaxed(&ct_log_window_start, now);
        atomic_store_relaxed(&ct_log_budget, (int) rate);
    }

    atomic_sub_explicit(&ct_log_budget, 1, &budget_before,
                        memory_order_relaxed);
    return budget_before > 0;
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
    case CT_LOG_R_SHUTDOWN:
    default:
        return "unknown";
    }
}

/* Logs 'conn's whole lifecycle -- creation and purge -- in one line.  See
 * the comment on conntrack_log_conn() in conntrack-log.h: this runs inline,
 * on whichever thread is already removing 'conn', with no ring and no
 * separate consumer thread. */
void
conntrack_log_conn(enum ct_log_reason reason, struct conn *conn)
{
    const struct conn_key *orig = &conn->key_node[CT_DIR_FWD].key;
    const struct conn_key *reply = &conn->key_node[CT_DIR_REV].key;
    long long purged_wall, age_ms, created_wall;
    uint32_t mark;
    struct ds ds;

    if (!ct_log_take_budget(time_msec())) {
        COVERAGE_INC(conntrack_log_ratelimited);
        return;
    }

    /* 'created' is in time_msec() (monotonic) units, immune to wall-clock
     * adjustments; reconstruct a wall-clock creation time from the current
     * wall time and that monotonic age, the same way a human-readable
     * 'created' timestamp would be computed anywhere else in this file. */
    age_ms = time_msec() - conn->created;
    purged_wall = time_wall_msec();
    created_wall = purged_wall - age_ms;

    ovs_mutex_lock(&conn->lock);
    mark = conn->mark;
    ovs_mutex_unlock(&conn->lock);

    ds_init(&ds);
    ds_put_cstr(&ds, "CT");

    switch (orig->nw_proto) {
    case IPPROTO_TCP:
        ds_put_cstr(&ds, " proto=tcp");
        break;
    case IPPROTO_UDP:
        ds_put_cstr(&ds, " proto=udp");
        break;
    case IPPROTO_ICMP:
        ds_put_cstr(&ds, " proto=icmp");
        break;
    case IPPROTO_ICMPV6:
        ds_put_cstr(&ds, " proto=icmpv6");
        break;
    default:
        ds_put_format(&ds, " proto=%"PRIu8, orig->nw_proto);
    }
    ds_put_format(&ds, " zone=%"PRIu16, orig->zone);
    ct_log_format_tuple(&ds, "orig", orig);
    ct_log_format_tuple(&ds, "reply", reply);

    if (conn->nat_action) {
        ds_put_format(&ds, " nat=%s%s%s",
                      conn->nat_action & NAT_ACTION_SNAT_ALL ? "snat" : "",
                      (conn->nat_action & NAT_ACTION_SNAT_ALL)
                      && (conn->nat_action & NAT_ACTION_DNAT_ALL) ? "," : "",
                      conn->nat_action & NAT_ACTION_DNAT_ALL ? "dnat" : "");
    }
    if (mark) {
        ds_put_format(&ds, " mark=%#"PRIx32, mark);
    }
    ds_put_cstr(&ds, " created=");
    ds_put_strftime_msec(&ds, "%Y-%m-%dT%H:%M:%S.###Z", created_wall, true);
    ds_put_cstr(&ds, " purged=");
    ds_put_strftime_msec(&ds, "%Y-%m-%dT%H:%M:%S.###Z", purged_wall, true);
    ds_put_format(&ds, " age=%lldms reason=%s",
                  age_ms, ct_log_reason_name(reason));

    VLOG_INFO("%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

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
     * a concurrent reader never sees a filter that is neither the old nor
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

void
conntrack_log_set(bool enable, unsigned int rate)
{
    atomic_store_relaxed(&ct_log_rate, rate);
    /* Release: pairs with the acquire in conntrack_log_enabled(), so a
     * reader that sees 'enabled' also sees a consistent zone filter. */
    atomic_store_explicit(&conntrack_log_enabled_flag, enable,
                          memory_order_release);
}

static void
ct_log_unixctl_set(struct unixctl_conn *conn, int argc, const char *argv[],
                   void *aux OVS_UNUSED)
{
    bool new_enabled, have_enabled = false, have_rate = false;
    bool have_zones = false, all_zones = false;
    unsigned int rate = 0;
    uint32_t *zone_words = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "enable")) {
            new_enabled = true;
            have_enabled = true;
        } else if (!strcmp(argv[i], "disable")) {
            new_enabled = false;
            have_enabled = true;
        } else if (!strncmp(argv[i], "rate=", 5)) {
            if (!str_to_uint(argv[i] + 5, 10, &rate)) {
                free(zone_words);
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
    if (have_enabled) {
        bool cur_enabled;

        atomic_read_relaxed(&conntrack_log_enabled_flag, &cur_enabled);
        if (new_enabled != cur_enabled) {
            atomic_store_explicit(&conntrack_log_enabled_flag, new_enabled,
                                  memory_order_release);
        }
    }
    unixctl_command_reply(conn, NULL);
}

static void
ct_log_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    bool enabled;
    unsigned int rate;

    atomic_read_relaxed(&conntrack_log_enabled_flag, &enabled);
    atomic_read_relaxed(&ct_log_rate, &rate);

    ds_put_format(&ds, "logging: %s\n", enabled ? "enabled" : "disabled");
    ds_put_cstr(&ds, "zones: ");
    ct_log_format_zones(&ds);
    ds_put_char(&ds, '\n');
    ds_put_format(&ds, "rate limit: %u lines/sec%s\n", rate,
                  rate ? "" : " (unlimited)");
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}
