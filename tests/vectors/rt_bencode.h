/*
 * rt_bencode.h - a reference canonical-bencode encoder for the Riptide
 * conformance oracle.
 *
 * This is NOT shipped in the extension; the shipped encoder is the LCB /
 * livecodescript one in src/riptide.lcb. This C encoder exists only to compute
 * the byte-exact known answers that both implementations must agree on
 * (03-conventions.md section 3.2: bencode with keys sorted lexicographically by
 * raw byte value), so that:
 *
 *   1. wire_vectors.c can assert the canonical bytes of the Riptide records and
 *      the BEP44 signing buffer, and
 *   2. the on-engine self-test (examples/riptide-tests.livecodescript) can be
 *      pinned to the SAME frozen answers, exactly as tests/vectors/README.md
 *      asks ("drive the same derivations through the sx* handlers").
 *
 * Canonical bencode, per the constitution:
 *   - integer    i<decimal>e     (no leading zeros; i0e for zero; no -0)
 *   - byte string <len>:<bytes>  (len decimal; holds arbitrary bytes safely)
 *   - list        l<items>e
 *   - dict        d<key-value ...>e, keys are byte strings sorted by raw byte
 *                 value, each key once
 *
 * The encoder is byte-safe: keys and values may contain NUL and any 0x00..0xff.
 */
#ifndef RT_BENCODE_H
#define RT_BENCODE_H

#include <stddef.h>

/* A growable byte buffer. */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} bbuf;

void bbuf_init(bbuf *b);
void bbuf_free(bbuf *b);
void bbuf_append(bbuf *b, const void *p, size_t n);

/* Primitive bencode emitters (append onto b). */
void benc_int(bbuf *b, long long value);
void benc_bytes(bbuf *b, const unsigned char *p, size_t n);
void benc_cstr(bbuf *b, const char *s);   /* byte string from a NUL-terminated C string */

/*
 * Dict builder. Collect entries in any order; bdict_finish sorts the keys by raw
 * byte value and emits the canonical d...e onto out. This mirrors what the LCB
 * encoder must do (sort at emit time, never trust insertion order).
 */
#define BDICT_MAX 32
typedef struct {
    unsigned char *key;
    size_t keylen;
    bbuf value;              /* already-bencoded value bytes */
} bdict_ent;

typedef struct {
    bdict_ent ent[BDICT_MAX];
    int n;
} bdict;

void bdict_init(bdict *d);
void bdict_add_int(bdict *d, const char *key, long long value);
void bdict_add_bytes(bdict *d, const char *key, const unsigned char *p, size_t n);
void bdict_add_cstr(bdict *d, const char *key, const char *s);
void bdict_add_raw(bdict *d, const char *key, const unsigned char *bencoded, size_t n);
void bdict_finish(bdict *d, bbuf *out);   /* sorts, emits d...e, frees entry values */

#endif /* RT_BENCODE_H */
