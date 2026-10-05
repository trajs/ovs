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
#include "esp.h"
#include <errno.h>
#include <string.h>
#include "byte-order.h"
#include "ovstest.h"
#include "util.h"

#define TEST_KEY "101112131415161718191a1b1c1d1e1fcafebabe"
#define TEST_PAYLOAD "OVS ESP known answer test vector"

/* Produced with the 'cryptography' Python module from TEST_KEY, IV
 * 0x0011223344556677, payload TEST_PAYLOAD and next header 4.
 *  - SPI 0x1000, sequence number 7.
 *  - SPI 0x1001, extended sequence number 0x100000005. */
static const char *kat_seq7 =
    "00001000000000070011223344556677"
    "6b646566a4cb5ffb8ae9320d838a07cc83405ce68e7003193ade723b8a3b01b8"
    "2246cdb5397447f5217f7a2a0edea54dcab9d890";
static const char *kat_esn =
    "00001001000000050011223344556677"
    "6b646566a4cb5ffb8ae9320d838a07cc83405ce68e7003193ade723b8a3b01b8"
    "2246cdb5d03e0fb3b624b02969575ee723f923a5";

struct test_pkt {
    uint8_t buf[256];
    size_t len;
};

static struct esp_sa_params
make_params(uint32_t spi, const char *key, bool esn, uint16_t window)
{
    struct esp_sa_params params;
    char *error;

    memset(&params, 0, sizeof params);
    params.spi = htonl(spi);
    params.sad_id = params.spi;
    params.tun_id = htonll(spi);
    params.esn = esn;
    params.replay_window = window;
    error = esp_parse_key(key, &params);
    ovs_assert(!error);
    return params;
}

static void
from_hex(struct test_pkt *pkt, const char *hex)
{
    pkt->len = strlen(hex) / 2;
    ovs_assert(pkt->len <= sizeof pkt->buf);
    for (size_t i = 0; i < pkt->len; i++) {
        bool ok;

        pkt->buf[i] = hexits_value(&hex[2 * i], 2, &ok);
        ovs_assert(ok);
    }
}

static struct esp_header *
pkt_esp(struct test_pkt *pkt)
{
    return ALIGNED_CAST(struct esp_header *, pkt->buf);
}

static int
seal(struct esp_sa *sa, struct test_pkt *pkt, const void *payload,
     size_t payload_len)
{
    memcpy(pkt->buf + ESP_PREFIX_LEN, payload, payload_len);
    pkt->len = ESP_PREFIX_LEN + payload_len + esp_trailer_len(payload_len);
    ovs_assert(pkt->len <= sizeof pkt->buf);
    return esp_seal(sa, pkt_esp(pkt), payload_len, IPPROTO_IPIP);
}

static int
open_pkt(struct test_pkt *pkt, size_t *payload_len)
{
    uint8_t next_hdr;
    ovs_be64 tun_id;

    return esp_open(pkt_esp(pkt), pkt->len, &tun_id, &next_hdr, payload_len);
}

/* Seals a packet with sequence number 'seq' on 'out' and returns the result
 * of opening it. */
static int
send_seq(struct esp_sa *out, uint64_t seq)
{
    struct test_pkt pkt;
    size_t len;

    esp_sa_set_next_seq(out, seq);
    ovs_assert(!seal(out, &pkt, "x", 1));
    return open_pkt(&pkt, &len);
}

static void
test_parse_key(void)
{
    struct esp_sa_params params;
    char *error;

    error = esp_parse_key("0x" TEST_KEY, &params);
    ovs_assert(!error);
    ovs_assert(params.key_len == 20);
    ovs_assert(params.key[0] == 0x10 && params.key[19] == 0xbe);

    error = esp_parse_key(TEST_KEY TEST_KEY, &params);
    ovs_assert(error);
    free(error);

    error = esp_parse_key("101112131415161718191a1b1c1d1e1fcafebabz", &params);
    ovs_assert(error);
    free(error);

    error = esp_parse_key("", &params);
    ovs_assert(error);
    free(error);
}

static void
test_known_answer(void)
{
    struct esp_sa_params params = make_params(0x1000, TEST_KEY, false, 64);
    struct esp_sa *sa = esp_sa_create(&params);
    struct test_pkt pkt;
    uint8_t next_hdr;
    ovs_be64 tun_id;
    size_t len;

    ovs_assert(!esp_sad_insert(sa));

    /* Corrupted ICV, payload, or authenticated sequence number.  These must
     * not advance the anti-replay window. */
    from_hex(&pkt, kat_seq7);
    pkt.buf[pkt.len - 1] ^= 1;
    ovs_assert(open_pkt(&pkt, &len) == EBADMSG);
    from_hex(&pkt, kat_seq7);
    pkt.buf[ESP_PREFIX_LEN] ^= 1;
    ovs_assert(open_pkt(&pkt, &len) == EBADMSG);
    from_hex(&pkt, kat_seq7);
    pkt.buf[7] = 8;
    ovs_assert(open_pkt(&pkt, &len) == EBADMSG);

    /* Unknown SPI and truncated packet. */
    from_hex(&pkt, kat_seq7);
    pkt.buf[3] = 0x99;
    ovs_assert(open_pkt(&pkt, &len) == ENOENT);
    from_hex(&pkt, kat_seq7);
    pkt.len = ESP_PREFIX_LEN + ESP_ICV_LEN + 1;
    ovs_assert(open_pkt(&pkt, &len) == EINVAL);

    from_hex(&pkt, kat_seq7);
    ovs_assert(!esp_open(pkt_esp(&pkt), pkt.len, &tun_id, &next_hdr, &len));
    ovs_assert(tun_id == htonll(0x1000));
    ovs_assert(next_hdr == 4);
    ovs_assert(len == strlen(TEST_PAYLOAD));
    ovs_assert(!memcmp(pkt.buf + ESP_PREFIX_LEN, TEST_PAYLOAD, len));

    /* Replayed. */
    from_hex(&pkt, kat_seq7);
    ovs_assert(open_pkt(&pkt, &len) == EALREADY);

    esp_sad_remove(sa);
    esp_sa_destroy(sa);
}

static void
test_round_trip(void)
{
    static const char *keys[] = {
        TEST_KEY,
        "000102030405060708090a0b0c0d0e0f1011121314151617deadbeef",
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1fdeadbeef",
    };

    for (size_t k = 0; k < ARRAY_SIZE(keys); k++) {
        for (int esn = 0; esn < 2; esn++) {
            struct esp_sa_params params = make_params(0x2000, keys[k],
                                                      esn, 64);
            struct esp_sa *out = esp_sa_create(&params);
            struct esp_sa *in = esp_sa_create(&params);
            uint8_t payload[100];

            ovs_assert(out && in);
            ovs_assert(!esp_sad_insert(in));
            for (size_t i = 0; i < sizeof payload; i++) {
                payload[i] = i * 7;
            }

            for (size_t n = 0; n <= sizeof payload; n++) {
                struct test_pkt pkt;
                size_t len;

                ovs_assert(!seal(out, &pkt, payload, n));
                ovs_assert((pkt.len - ESP_PREFIX_LEN - ESP_ICV_LEN) % 4 == 0);
                if (n >= 16) {
                    ovs_assert(memcmp(pkt.buf + ESP_PREFIX_LEN, payload, n));
                }
                ovs_assert(!open_pkt(&pkt, &len));
                ovs_assert(len == n);
                ovs_assert(!memcmp(pkt.buf + ESP_PREFIX_LEN, payload, n));
            }

            esp_sad_remove(in);
            esp_sa_destroy(in);
            esp_sa_destroy(out);
        }
    }
}

static void
test_replay_window(void)
{
    struct esp_sa_params params = make_params(0x3000, TEST_KEY, false, 64);
    struct esp_sa *out = esp_sa_create(&params);
    struct esp_sa *in = esp_sa_create(&params);

    ovs_assert(!esp_sad_insert(in));

    ovs_assert(send_seq(out, 0) == EALREADY);   /* 0 is never valid. */
    ovs_assert(!send_seq(out, 200));
    ovs_assert(!send_seq(out, 137));            /* Oldest in window. */
    ovs_assert(send_seq(out, 136) == EALREADY); /* Too old. */
    ovs_assert(send_seq(out, 137) == EALREADY); /* Duplicate. */
    ovs_assert(!send_seq(out, 199));
    ovs_assert(!send_seq(out, 263));            /* Slides by 63. */
    ovs_assert(send_seq(out, 199) == EALREADY);
    ovs_assert(!send_seq(out, 200 + 64));
    ovs_assert(!send_seq(out, 10000));          /* Slides beyond the window. */
    ovs_assert(!send_seq(out, 9999));

    /* Without ESN the sequence number must not cycle. */
    ovs_assert(!send_seq(out, UINT32_MAX));
    struct test_pkt pkt;
    ovs_assert(seal(out, &pkt, "x", 1) == ERANGE);

    esp_sad_remove(in);
    esp_sa_destroy(in);
    esp_sa_destroy(out);

    /* Anti-replay disabled. */
    params = make_params(0x3001, TEST_KEY, false, 0);
    out = esp_sa_create(&params);
    in = esp_sa_create(&params);
    ovs_assert(!esp_sad_insert(in));
    ovs_assert(!send_seq(out, 5));
    ovs_assert(!send_seq(out, 5));
    esp_sad_remove(in);
    esp_sa_destroy(in);
    esp_sa_destroy(out);
}

static void
test_esn(void)
{
    struct esp_sa_params params = make_params(0x1001, TEST_KEY, true, 64);
    struct esp_sa *out = esp_sa_create(&params);
    struct esp_sa *in = esp_sa_create(&params);
    const uint64_t wrap = UINT64_C(1) << 32;
    struct test_pkt pkt;
    size_t len;

    ovs_assert(!esp_sad_insert(in));

    /* A receiver cannot follow a jump of nearly 2**32. */
    ovs_assert(send_seq(out, wrap - 10) == EALREADY);

    ovs_assert(!send_seq(out, wrap / 2));
    ovs_assert(!send_seq(out, wrap - 16));
    ovs_assert(!send_seq(out, wrap - 1));
    ovs_assert(!send_seq(out, wrap + 1));       /* Low 32 bits wrap. */
    ovs_assert(!send_seq(out, wrap - 2));       /* Still in the window. */
    ovs_assert(send_seq(out, wrap - 1) == EALREADY);

    /* The known-answer packet has sequence number 2**32 + 5. */
    from_hex(&pkt, kat_esn);
    ovs_assert(!open_pkt(&pkt, &len));
    ovs_assert(len == strlen(TEST_PAYLOAD));
    ovs_assert(!memcmp(pkt.buf + ESP_PREFIX_LEN, TEST_PAYLOAD, len));

    /* Too far ahead: authenticated as 2**32 + 7, which fails. */
    ovs_assert(send_seq(out, 3 * wrap + 7) == EBADMSG);

    esp_sad_remove(in);
    esp_sa_destroy(in);
    esp_sa_destroy(out);

    /* ESN requires an anti-replay window. */
    params.replay_window = 0;
    ovs_assert(!esp_sa_create(&params));
}

static void
test_sad(void)
{
    struct esp_sa_params p1 = make_params(0x4000, TEST_KEY, false, 64);
    struct esp_sa_params p2 = make_params(0x4000, TEST_KEY, true, 64);
    struct esp_sa_params p3 = make_params(0x4000, TEST_KEY, false, 0);
    const ovs_be32 spi = htonl(0x4000);
    struct esp_sa *sa1, *sa2, *sa3;
    struct in6_addr peer;

    /* An outbound SA with the same SPI, for a peer. */
    in6_addr_set_mapped_ipv4(&peer, htonl(0x01010101));
    p3.dst = peer;

    sa1 = esp_sa_create(&p1);
    sa2 = esp_sa_create(&p2);
    sa3 = esp_sa_create(&p3);

    ovs_assert(!esp_sa_params_equal(&p1, &p2));
    ovs_assert(!esp_sad_lookup(spi, &in6addr_any));
    ovs_assert(!esp_sad_insert(sa1));
    ovs_assert(esp_sad_insert(sa2) == EEXIST);
    ovs_assert(!esp_sad_insert(sa3));
    ovs_assert(esp_sad_lookup(spi, &in6addr_any) == sa1);
    ovs_assert(esp_sad_lookup(spi, &peer) == sa3);
    esp_sad_replace(sa1, sa2);
    ovs_assert(esp_sad_lookup(spi, &in6addr_any) == sa2);
    esp_sad_remove(sa2);
    ovs_assert(!esp_sad_lookup(spi, &in6addr_any));
    ovs_assert(esp_sad_lookup(spi, &peer) == sa3);
    esp_sad_remove(sa3);
    ovs_assert(!esp_sad_lookup(spi, &peer));

    /* An SA rekeyed by IKE is looked up by a stable ID, but packets carry its
     * SPI, and received packets get its tunnel ID. */
    struct esp_sa_params p4 = make_params(0x5000, TEST_KEY, false, 64);
    struct esp_sa_params p5 = make_params(0x5000, TEST_KEY, false, 64);
    struct esp_sa *out, *in;
    struct test_pkt pkt;
    ovs_be64 tun_id;
    uint8_t next_hdr;
    size_t len;

    p4.sad_id = htonl(7);
    p4.dst = peer;
    p5.tun_id = htonll(7);
    out = esp_sa_create(&p4);
    in = esp_sa_create(&p5);
    ovs_assert(!esp_sad_insert(out));
    ovs_assert(!esp_sad_insert(in));
    ovs_assert(esp_sad_lookup(htonl(7), &peer) == out);
    ovs_assert(!esp_sad_lookup(htonl(0x5000), &peer));
    ovs_assert(!seal(out, &pkt, "x", 1));
    ovs_assert(get_16aligned_be32(&pkt_esp(&pkt)->spi) == htonl(0x5000));
    ovs_assert(!esp_open(pkt_esp(&pkt), pkt.len, &tun_id, &next_hdr, &len));
    ovs_assert(tun_id == htonll(7));
    esp_sad_remove(out);
    esp_sad_remove(in);
    esp_sa_destroy(out);
    esp_sa_destroy(in);

    esp_sa_destroy(sa1);
    esp_sa_destroy(sa2);
    esp_sa_destroy(sa3);
}

static void
test_esp_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    if (!esp_is_supported()) {
        exit(77);
    }

    test_parse_key();
    test_known_answer();
    test_round_trip();
    test_replay_window();
    test_esn();
    test_sad();
}

OVSTEST_REGISTER("test-esp", test_esp_main);
