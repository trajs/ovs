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

#ifndef ESP_H
#define ESP_H 1

/* IPsec Encapsulating Security Payload (ESP, RFC 4303) with AES-GCM
 * (RFC 4106), for tunnels in the userspace datapath.
 *
 * A Security Association (SA) holds the keys and sequence number state for
 * one direction of a tunnel.  SAs are published in a global SA database
 * (SAD), where datapath threads look them up:
 *
 *   - An outbound SA by its SPI and the address of the peer, which are both
 *     in the tunnel header that the datapath pushes.
 *
 *   - An inbound SA by its SPI alone, as this host chose the SPI.  Received
 *     packets are authenticated and decrypted before it is known which tunnel
 *     port they belong to.
 *
 * esp_seal() and esp_open() may be called from any thread, including PMD
 * threads, concurrently for the same SA.  All other functions must be called
 * from a single thread (the main thread in ovs-vswitchd).  An SA that has
 * been removed from the SAD or is no longer published to other threads must
 * be freed with esp_sa_destroy_postponed(). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "compiler.h"
#include "openvswitch/types.h"
#include "packets.h"

/* ESP_HEADER_LEN, struct esp_header and ESP_TRAILER_LEN are in packets.h. */
#define ESP_IV_LEN      8
#define ESP_ICV_LEN     16
#define ESP_SALT_LEN    4

/* Bytes between the start of the ESP header and the encrypted payload. */
#define ESP_PREFIX_LEN  (ESP_HEADER_LEN + ESP_IV_LEN)

/* An AES-256 key followed by the 4-byte salt, as in RFC 4106. */
#define ESP_MAX_KEY_LEN (32 + ESP_SALT_LEN)

#define ESP_DEFAULT_REPLAY_WINDOW 64
#define ESP_MAX_REPLAY_WINDOW     4096

struct esp_sa_params {
    ovs_be32 spi;
    struct in6_addr dst;            /* Outbound: peer address.  Inbound: 0. */
    uint8_t key[ESP_MAX_KEY_LEN];   /* AES key followed by the salt. */
    uint8_t key_len;                /* Including the salt. */
    bool esn;                       /* Extended (64-bit) Sequence Numbers. */
    uint16_t replay_window;         /* Inbound only, in packets; 0 = off,
                                     * which is invalid with 'esn'. */
};

bool esp_is_supported(void);

char *esp_parse_key(const char *, struct esp_sa_params *)
    OVS_WARN_UNUSED_RESULT;
bool esp_sa_params_equal(const struct esp_sa_params *,
                         const struct esp_sa_params *);

struct esp_sa *esp_sa_create(const struct esp_sa_params *);
void esp_sa_destroy(struct esp_sa *);
void esp_sa_destroy_postponed(struct esp_sa *);
const struct esp_sa_params *esp_sa_get_params(const struct esp_sa *);
const char *esp_sa_cipher_name(const struct esp_sa *);

struct esp_sa_stats {
    uint64_t n_packets;         /* Sent (outbound) or received (inbound). */
    uint64_t n_bytes;           /* Of the inner packets. */
    uint64_t n_replayed;        /* Inbound only. */
    uint64_t n_auth_failed;     /* Inbound only. */
    uint64_t n_malformed;       /* Inbound only. */
    uint64_t n_tx_errors;       /* Outbound only. */
    uint64_t tx_seq;            /* Outbound: last sequence number sent. */
    uint64_t rx_seq;            /* Inbound: highest sequence number received,
                                 * if the anti-replay window is enabled. */
};
void esp_sa_get_stats(const struct esp_sa *, struct esp_sa_stats *);

int esp_sad_insert(struct esp_sa *);
void esp_sad_replace(struct esp_sa *old, struct esp_sa *new);
void esp_sad_remove(struct esp_sa *);
struct esp_sa *esp_sad_lookup(ovs_be32 spi, const struct in6_addr *dst);

size_t esp_trailer_len(size_t payload_len);
int esp_seal(struct esp_sa *, struct esp_header *, size_t payload_len,
             uint8_t next_hdr);
int esp_open(struct esp_header *, size_t len, ovs_be32 *spi,
             uint8_t *next_hdr, size_t *payload_len);

/* For testing only. */
void esp_sa_set_next_seq(struct esp_sa *, uint64_t seq);

#endif /* esp.h */
