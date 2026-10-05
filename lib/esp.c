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

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#include <openssl/evp.h>
#endif

#include "byte-order.h"
#include "cmap.h"
#include "coverage.h"
#include "hash.h"
#include "openvswitch/dynamic-string.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "random.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(esp);

COVERAGE_DEFINE(esp_tx_seq_exhausted);
COVERAGE_DEFINE(esp_tx_crypto_error);
COVERAGE_DEFINE(esp_rx_malformed);
COVERAGE_DEFINE(esp_rx_no_sa);
COVERAGE_DEFINE(esp_rx_replay);
COVERAGE_DEFINE(esp_rx_auth_failed);

struct esp_sa {
    struct cmap_node node;          /* In 'esp_sad', for inbound SAs. */
    struct esp_sa_params params;
    uint64_t id;                    /* Unique, never 0. */
#ifdef HAVE_OPENSSL
    const EVP_CIPHER *cipher;
#endif

    /* Outbound.  The explicit IV of a packet is its sequence number XORed
     * with 'iv_salt', which is random per SA, so that a manually keyed SA
     * that restarts its sequence numbers does not reuse IVs. */
    atomic_uint64_t seq;            /* Last sequence number sent. */
    uint64_t iv_salt;

    /* Statistics, of sent packets for an outbound SA and of received ones
     * for an inbound SA.  'n_bytes' counts the bytes of the payload, that is
     * of the inner packets. */
    atomic_uint64_t n_packets;
    atomic_uint64_t n_bytes;
    atomic_uint64_t n_replayed;     /* Inbound: dropped as replays. */
    atomic_uint64_t n_auth_failed;  /* Inbound: failed authentication. */
    atomic_uint64_t n_malformed;    /* Inbound: bad padding or length. */
    atomic_uint64_t n_tx_errors;    /* Outbound: sequence exhausted or
                                     * encryption failed. */

    /* Inbound anti-replay window (RFC 4303 section 3.4.3 and appendix A).
     * Bit (N % replay_size) of 'replay_bitmap' is set if sequence number N
     * has been received, for N in (replay_top - replay_size, replay_top]. */
    struct ovs_mutex replay_mutex;
    uint64_t replay_top OVS_GUARDED;
    uint32_t replay_size;           /* In packets, multiple of 64. */
    uint64_t *replay_bitmap OVS_GUARDED;
};

#ifdef HAVE_OPENSSL
#define OVS_UNUSED_WITHOUT_OPENSSL
#else
#define OVS_UNUSED_WITHOUT_OPENSSL OVS_UNUSED
#endif

/* SA database, indexed by SPI and destination.  Only written by the main
 * thread. */
static struct cmap esp_sad = CMAP_INITIALIZER;

bool
esp_is_supported(void)
{
#ifdef HAVE_OPENSSL
    return true;
#else
    return false;
#endif
}

/* Parses 's', an AES-GCM key followed by a 4-byte salt as hexadecimal digits
 * with an optional "0x" prefix, into 'params'.  This is the format used by
 * "ip xfrm state ... aead 'rfc4106(gcm(aes))' <key> 128".
 *
 * Returns NULL if successful, otherwise a malloc()'d error message. */
char *
esp_parse_key(const char *s, struct esp_sa_params *params)
{
    size_t n_digits, key_len;

    if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2)) {
        s += 2;
    }

    n_digits = strlen(s);
    key_len = n_digits / 2;
    if (n_digits % 2
        || (key_len != 16 + ESP_SALT_LEN && key_len != 24 + ESP_SALT_LEN
            && key_len != 32 + ESP_SALT_LEN)) {
        return xasprintf("key must be 20, 28 or 36 bytes (an AES-128, -192 "
                         "or -256 key followed by a 4-byte salt), "
                         "got %"PRIuSIZE" hex digits", n_digits);
    }

    for (size_t i = 0; i < key_len; i++) {
        bool ok;

        params->key[i] = hexits_value(&s[2 * i], 2, &ok);
        if (!ok) {
            return xstrdup("key contains a non-hexadecimal digit");
        }
    }
    params->key_len = key_len;

    return NULL;
}

bool
esp_sa_params_equal(const struct esp_sa_params *a,
                    const struct esp_sa_params *b)
{
    return (a->spi == b->spi
            && ipv6_addr_equals(&a->dst, &b->dst)
            && a->sad_id == b->sad_id
            && a->tun_id == b->tun_id
            && a->key_len == b->key_len
            && !memcmp(a->key, b->key, a->key_len)
            && a->esn == b->esn
            && a->replay_window == b->replay_window);
}

/* Returns a new SA for 'params', or NULL if ESP is not supported or 'params'
 * is invalid. */
struct esp_sa *
esp_sa_create(const struct esp_sa_params *params OVS_UNUSED_WITHOUT_OPENSSL)
{
#ifdef HAVE_OPENSSL
    static atomic_uint64_t next_id = 1;
    const EVP_CIPHER *cipher;
    struct esp_sa *sa;

    switch (params->key_len - ESP_SALT_LEN) {
    case 16:
        cipher = EVP_aes_128_gcm();
        break;
    case 24:
        cipher = EVP_aes_192_gcm();
        break;
    case 32:
        cipher = EVP_aes_256_gcm();
        break;
    default:
        return NULL;
    }

    /* An inbound SA needs the anti-replay window to infer the high half of
     * extended sequence numbers. */
    bool inbound = !ipv6_addr_is_set(&params->dst);
    if (params->replay_window > ESP_MAX_REPLAY_WINDOW
        || (inbound && params->esn && !params->replay_window)) {
        return NULL;
    }

    sa = xzalloc(sizeof *sa);
    sa->params = *params;
    atomic_add_relaxed(&next_id, 1, &sa->id);
    sa->cipher = cipher;
    atomic_init(&sa->seq, 0);
    atomic_init(&sa->n_packets, 0);
    atomic_init(&sa->n_bytes, 0);
    atomic_init(&sa->n_replayed, 0);
    atomic_init(&sa->n_auth_failed, 0);
    atomic_init(&sa->n_malformed, 0);
    atomic_init(&sa->n_tx_errors, 0);
    sa->iv_salt = random_uint64();

    ovs_mutex_init(&sa->replay_mutex);
    sa->replay_size = ROUND_UP(params->replay_window, 64);
    if (sa->replay_size) {
        sa->replay_bitmap = xzalloc(sa->replay_size / 8);
    }

    return sa;
#else
    return NULL;
#endif
}

void
esp_sa_destroy(struct esp_sa *sa)
{
    if (sa) {
        ovs_mutex_destroy(&sa->replay_mutex);
        free(sa->replay_bitmap);
#ifdef HAVE_OPENSSL
        OPENSSL_cleanse(sa->params.key, sizeof sa->params.key);
#endif
        free(sa);
    }
}

/* Destroys 'sa' once no thread can be using it anymore. */
void
esp_sa_destroy_postponed(struct esp_sa *sa)
{
    if (sa) {
        ovsrcu_postpone(esp_sa_destroy, sa);
    }
}

const struct esp_sa_params *
esp_sa_get_params(const struct esp_sa *sa)
{
    return &sa->params;
}

#ifdef HAVE_OPENSSL
static void
esp_stat_inc(atomic_uint64_t *counter, uint64_t n)
{
    uint64_t orig;

    atomic_add_relaxed(counter, n, &orig);
}
#endif

static uint64_t
esp_stat_read(const atomic_uint64_t *counter_)
{
    atomic_uint64_t *counter = CONST_CAST(atomic_uint64_t *, counter_);
    uint64_t value;

    atomic_read_relaxed(counter, &value);
    return value;
}

/* Stores a snapshot of the statistics of 'sa' in 'stats'. */
void
esp_sa_get_stats(const struct esp_sa *sa_, struct esp_sa_stats *stats)
{
    struct esp_sa *sa = CONST_CAST(struct esp_sa *, sa_);

    stats->n_packets = esp_stat_read(&sa->n_packets);
    stats->n_bytes = esp_stat_read(&sa->n_bytes);
    stats->n_replayed = esp_stat_read(&sa->n_replayed);
    stats->n_auth_failed = esp_stat_read(&sa->n_auth_failed);
    stats->n_malformed = esp_stat_read(&sa->n_malformed);
    stats->n_tx_errors = esp_stat_read(&sa->n_tx_errors);
    stats->tx_seq = esp_stat_read(&sa->seq);

    ovs_mutex_lock(&sa->replay_mutex);
    stats->rx_seq = sa->replay_top;
    ovs_mutex_unlock(&sa->replay_mutex);
}

/* Appends to 'ds' a description of 'sa', labeled 'dir', and its
 * statistics. */
void
esp_sa_format(struct ds *ds, const char *dir, const struct esp_sa *sa,
              bool inbound)
{
    const struct esp_sa_params *p = esp_sa_get_params(sa);
    struct esp_sa_stats stats;

    esp_sa_get_stats(sa, &stats);
    ds_put_format(ds, "  %s: spi 0x%08"PRIx32", %s, esn %s", dir,
                  ntohl(p->spi), esp_sa_cipher_name(sa),
                  p->esn ? "on" : "off");
    if (inbound) {
        ds_put_format(ds, ", replay window %"PRIu16"\n", p->replay_window);
        ds_put_format(ds, "    packets %"PRIu64", bytes %"PRIu64,
                      stats.n_packets, stats.n_bytes);
        if (p->replay_window) {
            ds_put_format(ds, ", highest seq %"PRIu64, stats.rx_seq);
        }
        ds_put_format(ds, "\n    replayed %"PRIu64", auth failed %"PRIu64
                      ", malformed %"PRIu64"\n", stats.n_replayed,
                      stats.n_auth_failed, stats.n_malformed);
    } else {
        ds_put_format(ds, "\n    packets %"PRIu64", bytes %"PRIu64
                      ", last seq %"PRIu64", errors %"PRIu64"\n",
                      stats.n_packets, stats.n_bytes, stats.tx_seq,
                      stats.n_tx_errors);
    }
}

/* Returns the name of the cipher of 'sa', e.g. "aes128-gcm16". */
const char *
esp_sa_cipher_name(const struct esp_sa *sa)
{
    switch (sa->params.key_len - ESP_SALT_LEN) {
    case 16:
        return "aes128-gcm16";
    case 24:
        return "aes192-gcm16";
    case 32:
        return "aes256-gcm16";
    default:
        return "unknown";
    }
}

/* Makes the next packet sent on outbound SA 'sa' use sequence number 'seq'.
 * For testing only. */
void
esp_sa_set_next_seq(struct esp_sa *sa, uint64_t seq)
{
    atomic_store_relaxed(&sa->seq, seq - 1);
}

/* SA database. */

static uint32_t
esp_sad_hash(ovs_be32 spi, const struct in6_addr *dst)
{
    return hash_bytes(dst, sizeof *dst, (OVS_FORCE uint32_t) spi);
}

/* Adds 'sa' to the SAD.  Returns 0 if successful, EEXIST if an SA with the
 * same SPI and destination is already present. */
int
esp_sad_insert(struct esp_sa *sa)
{
    const struct esp_sa_params *p = &sa->params;

    if (esp_sad_lookup(p->sad_id, &p->dst)) {
        return EEXIST;
    }
    cmap_insert(&esp_sad, &sa->node, esp_sad_hash(p->sad_id, &p->dst));
    return 0;
}

/* Replaces 'old', which must be in the SAD, by 'new'.  Their SPIs and
 * destinations must be the same.  Packets processed meanwhile use one or the
 * other. */
void
esp_sad_replace(struct esp_sa *old, struct esp_sa *new)
{
    const struct esp_sa_params *p = &new->params;

    ovs_assert(old->params.sad_id == p->sad_id
               && ipv6_addr_equals(&old->params.dst, &p->dst));
    cmap_replace(&esp_sad, &old->node, &new->node,
                 esp_sad_hash(p->sad_id, &p->dst));
}

void
esp_sad_remove(struct esp_sa *sa)
{
    const struct esp_sa_params *p = &sa->params;

    cmap_remove(&esp_sad, &sa->node, esp_sad_hash(p->sad_id, &p->dst));
}

/* Returns the SA with 'sad_id' and 'dst' from the SAD, or NULL.  'dst' is
 * the peer's address for an outbound SA, all-zeros for an inbound SA.  See
 * struct esp_sa_params for the meaning of 'sad_id'. */
struct esp_sa *
esp_sad_lookup(ovs_be32 sad_id, const struct in6_addr *dst)
{
    struct esp_sa *sa;

    CMAP_FOR_EACH_WITH_HASH (sa, node, esp_sad_hash(sad_id, dst), &esp_sad) {
        if (sa->params.sad_id == sad_id
            && ipv6_addr_equals(&sa->params.dst, dst)) {
            return sa;
        }
    }
    return NULL;
}

#ifdef HAVE_OPENSSL
/* Anti-replay window. */

/* Determines the full sequence number of a packet whose transmitted (low 32)
 * bits are 'seq_lo', per RFC 4303 appendix A.2.1.  Returns false if it would
 * be outside the 64-bit sequence number space. */
static bool
esp_replay_infer_seq(const struct esp_sa *sa, uint32_t seq_lo,
                     uint64_t *seqp)
    OVS_REQUIRES(sa->replay_mutex)
{
    uint32_t top_lo = sa->replay_top;
    uint32_t top_hi = sa->replay_top >> 32;
    uint32_t bottom = top_lo - sa->replay_size + 1;
    uint32_t seq_hi;

    if (!sa->params.esn) {
        *seqp = seq_lo;
        return true;
    }

    if (top_lo >= sa->replay_size - 1) {
        /* The window lies within one 2**32 subspace. */
        if (seq_lo >= bottom) {
            seq_hi = top_hi;
        } else if (top_hi == UINT32_MAX) {
            return false;
        } else {
            seq_hi = top_hi + 1;
        }
    } else {
        /* The window spans two subspaces. */
        if (seq_lo >= bottom) {
            if (!top_hi) {
                return false;
            }
            seq_hi = top_hi - 1;
        } else {
            seq_hi = top_hi;
        }
    }

    *seqp = ((uint64_t) seq_hi << 32) | seq_lo;
    return true;
}

static bool
esp_replay_bit(const struct esp_sa *sa, uint64_t seq)
    OVS_REQUIRES(sa->replay_mutex)
{
    uint32_t bit = seq % sa->replay_size;

    return sa->replay_bitmap[bit / 64] & (UINT64_C(1) << (bit % 64));
}

static bool
esp_replay_check__(const struct esp_sa *sa, uint64_t seq)
    OVS_REQUIRES(sa->replay_mutex)
{
    if (!seq) {
        return false;
    } else if (seq > sa->replay_top) {
        return true;
    } else if (sa->replay_top - seq >= sa->replay_size) {
        return false;
    } else {
        return !esp_replay_bit(sa, seq);
    }
}

/* Checks, before authenticating it, whether a packet with transmitted
 * sequence number 'seq_lo' may be accepted.  If so, stores its full sequence
 * number in '*seqp' and returns true. */
static bool
esp_replay_check(struct esp_sa *sa, uint32_t seq_lo, uint64_t *seqp)
{
    bool ok;

    if (!sa->replay_size) {
        *seqp = seq_lo;
        return true;
    }

    ovs_mutex_lock(&sa->replay_mutex);
    ok = (esp_replay_infer_seq(sa, seq_lo, seqp)
          && esp_replay_check__(sa, *seqp));
    ovs_mutex_unlock(&sa->replay_mutex);

    return ok;
}

/* Records that the authenticated packet with sequence number 'seq' has been
 * received.  Returns false if another thread received it meanwhile. */
static bool
esp_replay_update(struct esp_sa *sa, uint64_t seq)
{
    uint32_t bit;
    bool ok;

    if (!sa->replay_size) {
        return true;
    }

    ovs_mutex_lock(&sa->replay_mutex);
    ok = esp_replay_check__(sa, seq);
    if (ok) {
        if (seq > sa->replay_top) {
            uint64_t diff = seq - sa->replay_top;

            if (diff >= sa->replay_size) {
                memset(sa->replay_bitmap, 0, sa->replay_size / 8);
            } else {
                for (uint64_t s = sa->replay_top + 1; s < seq; s++) {
                    bit = s % sa->replay_size;
                    sa->replay_bitmap[bit / 64] &=
                        ~(UINT64_C(1) << (bit % 64));
                }
            }
            sa->replay_top = seq;
        }
        bit = seq % sa->replay_size;
        sa->replay_bitmap[bit / 64] |= UINT64_C(1) << (bit % 64);
    }
    ovs_mutex_unlock(&sa->replay_mutex);

    return ok;
}

#endif /* HAVE_OPENSSL */

/* Packet processing. */

/* Returns the number of bytes that must follow a payload of 'payload_len'
 * bytes: padding to a 4-byte boundary, the ESP trailer and the ICV. */
size_t
esp_trailer_len(size_t payload_len)
{
    size_t pad_len = (4 - (payload_len + ESP_TRAILER_LEN) % 4) % 4;

    return pad_len + ESP_TRAILER_LEN + ESP_ICV_LEN;
}

#ifdef HAVE_OPENSSL
/* Each thread keeps a few cipher contexts with their keys already expanded,
 * indexed by SA and direction.  A collision only costs a key expansion. */
#define ESP_CTX_CACHE_SIZE 16

struct esp_ctx_slot {
    uint64_t sa_id;                 /* 0 if unused. */
    bool enc;
    EVP_CIPHER_CTX *ctx;
};

struct esp_ctx_cache {
    struct esp_ctx_slot slots[ESP_CTX_CACHE_SIZE];
};

static ovsthread_key_t esp_ctx_cache_key;

static void
esp_ctx_cache_destroy(void *cache_)
{
    struct esp_ctx_cache *cache = cache_;

    for (size_t i = 0; i < ESP_CTX_CACHE_SIZE; i++) {
        EVP_CIPHER_CTX_free(cache->slots[i].ctx);
    }
    free(cache);
}

static EVP_CIPHER_CTX *
esp_get_ctx(const struct esp_sa *sa, bool enc)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct esp_ctx_cache *cache;
    struct esp_ctx_slot *slot;

    if (ovsthread_once_start(&once)) {
        ovsthread_key_create(&esp_ctx_cache_key, esp_ctx_cache_destroy);
        ovsthread_once_done(&once);
    }

    cache = ovsthread_getspecific(esp_ctx_cache_key);
    if (!cache) {
        cache = xzalloc(sizeof *cache);
        ovsthread_setspecific(esp_ctx_cache_key, cache);
    }

    slot = &cache->slots[(sa->id * 2 + enc) % ESP_CTX_CACHE_SIZE];

    if (!slot->ctx) {
        slot->ctx = EVP_CIPHER_CTX_new();
        if (!slot->ctx) {
            return NULL;
        }
    }
    if (slot->sa_id != sa->id || slot->enc != enc) {
        slot->sa_id = 0;
        if (!EVP_CipherInit_ex(slot->ctx, sa->cipher, NULL, sa->params.key,
                               NULL, enc)) {
            return NULL;
        }
        slot->sa_id = sa->id;
        slot->enc = enc;
    }
    return slot->ctx;
}

/* Builds the AES-GCM nonce and additional authenticated data for a packet
 * with ESP header 'esp' and full sequence number 'seq' (RFC 4106 section 5).
 * Returns the length of the AAD. */
static size_t
esp_gcm_prepare(const struct esp_sa *sa, const struct esp_header *esp,
                uint64_t seq, uint8_t nonce[ESP_SALT_LEN + ESP_IV_LEN],
                uint8_t aad[12])
{
    ovs_be32 spi = get_16aligned_be32(&esp->spi);
    ovs_be32 seq_hi = htonl(seq >> 32);
    ovs_be32 seq_lo = htonl(seq);

    memcpy(nonce, &sa->params.key[sa->params.key_len - ESP_SALT_LEN],
           ESP_SALT_LEN);
    memcpy(nonce + ESP_SALT_LEN, esp + 1, ESP_IV_LEN);

    memcpy(aad, &spi, 4);
    if (sa->params.esn) {
        memcpy(aad + 4, &seq_hi, 4);
        memcpy(aad + 8, &seq_lo, 4);
        return 12;
    } else {
        memcpy(aad + 4, &seq_lo, 4);
        return 8;
    }
}
#endif

/* Encrypts a packet for outbound SA 'sa'.
 *
 * 'esp' must be followed by ESP_IV_LEN bytes of space for the IV, then by
 * 'payload_len' bytes of payload whose type is 'next_hdr' (an IP protocol
 * number), then by esp_trailer_len(payload_len) bytes of space.  Fills in the
 * ESP header, IV, padding, trailer and ICV, and encrypts the payload, padding
 * and trailer in place.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
esp_seal(struct esp_sa *sa OVS_UNUSED_WITHOUT_OPENSSL,
         struct esp_header *esp OVS_UNUSED_WITHOUT_OPENSSL,
         size_t payload_len OVS_UNUSED_WITHOUT_OPENSSL,
         uint8_t next_hdr OVS_UNUSED_WITHOUT_OPENSSL)
{
#ifdef HAVE_OPENSSL
    uint8_t *payload = (uint8_t *) esp + ESP_PREFIX_LEN;
    size_t ct_len = esp_trailer_len(payload_len) - ESP_ICV_LEN + payload_len;
    size_t pad_len = ct_len - payload_len - ESP_TRAILER_LEN;
    uint8_t nonce[ESP_SALT_LEN + ESP_IV_LEN];
    uint8_t *trailer = payload + payload_len;
    EVP_CIPHER_CTX *ctx;
    uint8_t aad[12];
    size_t aad_len;
    uint64_t seq;
    ovs_be64 iv;
    int len;

    atomic_add_relaxed(&sa->seq, 1, &seq);
    seq++;
    if (OVS_UNLIKELY(sa->params.esn ? !seq : seq > UINT32_MAX)) {
        /* RFC 4303 section 3.3.3: the sequence number must not cycle. */
        COVERAGE_INC(esp_tx_seq_exhausted);
        esp_stat_inc(&sa->n_tx_errors, 1);
        return ERANGE;
    }

    for (size_t i = 0; i < pad_len; i++) {
        trailer[i] = i + 1;
    }
    trailer[pad_len] = pad_len;
    trailer[pad_len + 1] = next_hdr;

    put_16aligned_be32(&esp->spi, sa->params.spi);
    put_16aligned_be32(&esp->seq_no, htonl(seq));
    iv = htonll(seq ^ sa->iv_salt);
    memcpy(esp + 1, &iv, ESP_IV_LEN);

    aad_len = esp_gcm_prepare(sa, esp, seq, nonce, aad);

    ctx = esp_get_ctx(sa, true);
    if (OVS_UNLIKELY(!ctx
                     || !EVP_CipherInit_ex(ctx, NULL, NULL, NULL, nonce, 1)
                     || !EVP_CipherUpdate(ctx, NULL, &len, aad, aad_len)
                     || !EVP_CipherUpdate(ctx, payload, &len, payload, ct_len)
                     || !EVP_CipherFinal_ex(ctx, payload + len, &len)
                     || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                             ESP_ICV_LEN,
                                             payload + ct_len))) {
        COVERAGE_INC(esp_tx_crypto_error);
        esp_stat_inc(&sa->n_tx_errors, 1);
        return EIO;
    }

    esp_stat_inc(&sa->n_packets, 1);
    esp_stat_inc(&sa->n_bytes, payload_len);
    return 0;
#else
    return EOPNOTSUPP;
#endif
}

/* Authenticates and decrypts the 'len'-byte ESP packet that starts at 'esp',
 * using the inbound SA for its SPI, and checks it against the SA's
 * anti-replay window.
 *
 * If successful, stores the SA's tunnel ID in '*tun_id', the protocol of the
 * payload in
 * '*next_hdr' and its length in '*payload_len', and returns 0.  The payload
 * starts ESP_PREFIX_LEN bytes after 'esp'.  Otherwise, returns a positive
 * errno value. */
int
esp_open(struct esp_header *esp OVS_UNUSED_WITHOUT_OPENSSL,
         size_t len OVS_UNUSED_WITHOUT_OPENSSL,
         ovs_be64 *tun_id OVS_UNUSED_WITHOUT_OPENSSL,
         uint8_t *next_hdr OVS_UNUSED_WITHOUT_OPENSSL,
         size_t *payload_len OVS_UNUSED_WITHOUT_OPENSSL)
{
#ifdef HAVE_OPENSSL
    uint8_t *payload = (uint8_t *) esp + ESP_PREFIX_LEN;
    uint8_t nonce[ESP_SALT_LEN + ESP_IV_LEN];
    EVP_CIPHER_CTX *ctx;
    uint8_t *trailer;
    struct esp_sa *sa;
    uint8_t *pad;
    uint8_t aad[12];
    size_t aad_len;
    size_t ct_len;
    size_t pad_len;
    uint32_t seq_lo;
    uint64_t seq;
    int out_len;

    if (OVS_UNLIKELY(len < ESP_PREFIX_LEN + ESP_TRAILER_LEN + ESP_ICV_LEN)) {
        COVERAGE_INC(esp_rx_malformed);
        return EINVAL;
    }
    ct_len = len - ESP_PREFIX_LEN - ESP_ICV_LEN;

    sa = esp_sad_lookup(get_16aligned_be32(&esp->spi), &in6addr_any);
    if (OVS_UNLIKELY(!sa)) {
        COVERAGE_INC(esp_rx_no_sa);
        return ENOENT;
    }

    seq_lo = ntohl(get_16aligned_be32(&esp->seq_no));
    if (OVS_UNLIKELY(!esp_replay_check(sa, seq_lo, &seq))) {
        COVERAGE_INC(esp_rx_replay);
        esp_stat_inc(&sa->n_replayed, 1);
        return EALREADY;
    }

    aad_len = esp_gcm_prepare(sa, esp, seq, nonce, aad);

    ctx = esp_get_ctx(sa, false);
    if (OVS_UNLIKELY(!ctx
                     || !EVP_CipherInit_ex(ctx, NULL, NULL, NULL, nonce, 0)
                     || !EVP_CipherUpdate(ctx, NULL, &out_len, aad, aad_len)
                     || !EVP_CipherUpdate(ctx, payload, &out_len, payload,
                                          ct_len)
                     || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                             ESP_ICV_LEN, payload + ct_len)
                     || EVP_CipherFinal_ex(ctx, payload + out_len,
                                           &out_len) <= 0)) {
        COVERAGE_INC(esp_rx_auth_failed);
        esp_stat_inc(&sa->n_auth_failed, 1);
        return EBADMSG;
    }

    if (OVS_UNLIKELY(!esp_replay_update(sa, seq))) {
        COVERAGE_INC(esp_rx_replay);
        esp_stat_inc(&sa->n_replayed, 1);
        return EALREADY;
    }

    trailer = payload + ct_len - ESP_TRAILER_LEN;
    pad_len = trailer[0];
    if (OVS_UNLIKELY(pad_len + ESP_TRAILER_LEN > ct_len)) {
        goto malformed;
    }
    /* RFC 4303 section 2.4: the padding bytes are 1, 2, 3, ... */
    pad = trailer - pad_len;
    for (size_t i = 0; i < pad_len; i++) {
        if (OVS_UNLIKELY(pad[i] != i + 1)) {
            goto malformed;
        }
    }

    *tun_id = sa->params.tun_id;
    *next_hdr = trailer[1];
    *payload_len = ct_len - pad_len - ESP_TRAILER_LEN;
    esp_stat_inc(&sa->n_packets, 1);
    esp_stat_inc(&sa->n_bytes, *payload_len);
    return 0;

malformed:
    COVERAGE_INC(esp_rx_malformed);
    esp_stat_inc(&sa->n_malformed, 1);
    return EINVAL;
#else
    return EOPNOTSUPP;
#endif
}
