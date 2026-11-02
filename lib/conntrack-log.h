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

#ifndef CONNTRACK_LOG_H
#define CONNTRACK_LOG_H 1

#include <stdbool.h>
#include <stdint.h>

#include "conntrack-private.h"
#include "ovs-atomic.h"

/* Connection tracking event logging.
 *
 * A connection's whole lifecycle is reported in a single line, written when
 * the connection is purged: by the existing 'ct_clean' sweep thread for a
 * normal expiry, or by whichever thread handles an explicit flush.  Neither
 * of those is ever a PMD thread, so the formatting and the vlog write happen
 * inline, right there -- no dedicated thread, no ring buffer, no additional
 * memory.  The only state this adds is the 'created' timestamp already
 * carried on struct conn.
 *
 * When logging is disabled, the cost on the datapath is one atomic load
 * (see conntrack_log_enabled()), and nothing is logged until a connection
 * that is already being torn down reaches conn_clean(). */

enum ct_log_reason {
    CT_LOG_R_EXPIRED,     /* Timed out, or replaced by a new connection. */
    CT_LOG_R_FLUSHED,     /* Removed by an explicit flush. */
    CT_LOG_R_SHUTDOWN,    /* Connection tracker destroyed; never logged. */
};

#define CT_LOG_ZONE_WORDS ((UINT16_MAX + 1) / 32)

extern atomic_bool conntrack_log_enabled_flag;
extern atomic_bool conntrack_log_all_zones;
extern atomic_uint32_t conntrack_log_zones[CT_LOG_ZONE_WORDS];

void conntrack_log_init(void);

/* Turns logging on or off, and sets the maximum rate in lines per second
 * (0 for unlimited). */
void conntrack_log_set(bool enable, unsigned int rate);

/* Returns true if logging is enabled for connections in conntrack zone
 * 'zone'.  The zone filter is only looked at once logging is enabled, so the
 * cost when it is disabled is one atomic load. */
static inline bool
conntrack_log_enabled(uint16_t zone)
{
    bool enabled, all_zones;

    atomic_read_explicit(&conntrack_log_enabled_flag, &enabled,
                          memory_order_acquire);
    if (OVS_LIKELY(!enabled)) {
        return false;
    }

    atomic_read_relaxed(&conntrack_log_all_zones, &all_zones);
    if (all_zones) {
        return true;
    } else {
        uint32_t word;

        atomic_read_relaxed(&conntrack_log_zones[zone / 32], &word);
        return word & (UINT32_C(1) << (zone % 32));
    }
}

/* Logs 'conn's lifecycle in one line: its tuple, how long it lived, and why
 * it was purged.  Called inline by whichever thread is already removing
 * 'conn' -- never a PMD.  Callers must check conntrack_log_enabled() first,
 * so the (small) cost of reading the connection is only paid when logging is
 * on; removal of 'conn' itself must already be unconditional and must never
 * be made to wait on this call, which may itself skip writing a line (and
 * count it as rate-limited) without affecting that removal at all. */
void conntrack_log_conn(enum ct_log_reason, struct conn *);

#endif /* conntrack-log.h */
