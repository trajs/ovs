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
 * Datapath threads (PMDs, the 'ct_clean' thread, appctl) only copy a small
 * fixed-size record into a lock-free bounded ring.  A dedicated 'ct_log'
 * thread drains the ring, formats the records and writes them through vlog
 * (module 'conntrack_log').  Producers never block, format text, allocate
 * memory or take locks: if the ring is full the event is dropped and counted.
 *
 * When logging is disabled, the cost on the datapath is one relaxed atomic
 * load (see conntrack_log_enabled()). */

enum ct_log_event_type {
    CT_LOG_NEW = 1 << 0,
    CT_LOG_DESTROY = 1 << 1,
};
#define CT_LOG_ALL_EVENTS (CT_LOG_NEW | CT_LOG_DESTROY)

enum ct_log_reason {
    CT_LOG_R_NONE,        /* Not applicable (NEW events). */
    CT_LOG_R_EXPIRED,     /* Timed out, or replaced by a new connection. */
    CT_LOG_R_FLUSHED,     /* Removed by an explicit flush. */
    CT_LOG_R_SHUTDOWN,    /* Connection tracker destroyed; never logged. */
};

#define CT_LOG_ZONE_WORDS ((UINT16_MAX + 1) / 32)

extern atomic_uint conntrack_log_mask;
extern atomic_bool conntrack_log_all_zones;
extern atomic_uint32_t conntrack_log_zones[CT_LOG_ZONE_WORDS];

void conntrack_log_init(void);

/* Sets the logged events ('mask' of enum ct_log_event_type; 0 disables) and
 * the maximum rate in events per second (0 for unlimited). */
void conntrack_log_set(unsigned int mask, unsigned int rate);

/* Returns true if any of the events in 'type' is currently being logged for
 * connections in conntrack zone 'zone'.  The zone filter is only looked at
 * once logging is enabled, so the cost when it is disabled is one atomic
 * load. */
static inline bool
conntrack_log_enabled(enum ct_log_event_type type, uint16_t zone)
{
    unsigned int mask;
    bool all_zones;

    atomic_read_explicit(&conntrack_log_mask, &mask, memory_order_acquire);
    if (OVS_LIKELY(!(mask & type))) {
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

/* Queues an event for 'conn'.  Callers must check conntrack_log_enabled()
 * first, so that the (small) cost of snapshotting the connection is only paid
 * when logging is on.  Safe to call from any thread. */
void conntrack_log_conn(enum ct_log_event_type, enum ct_log_reason,
                        struct conn *);

#endif /* conntrack-log.h */
