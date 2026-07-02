/*
 * rt_bencode.c - reference canonical-bencode encoder (see rt_bencode.h).
 */
#include "rt_bencode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg)
{
    fprintf(stderr, "rt_bencode: %s\n", msg);
    exit(2);
}

void bbuf_init(bbuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void bbuf_free(bbuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void bbuf_append(bbuf *b, const void *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < b->len + n) cap *= 2;
        unsigned char *nd = (unsigned char *)realloc(b->data, cap);
        if (!nd) die("out of memory");
        b->data = nd;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

void benc_int(bbuf *b, long long value)
{
    char tmp[32];
    /* %lld is the canonical decimal form: no leading zeros, "0" for zero, a
     * single leading '-' for negatives and never "-0". That is exactly the
     * bencode integer canonicalization the constitution requires. */
    int m = snprintf(tmp, sizeof tmp, "i%llde", value);
    if (m < 0 || (size_t)m >= sizeof tmp) die("int too long");
    bbuf_append(b, tmp, (size_t)m);
}

void benc_bytes(bbuf *b, const unsigned char *p, size_t n)
{
    char hdr[32];
    int m = snprintf(hdr, sizeof hdr, "%zu:", n);
    if (m < 0 || (size_t)m >= sizeof hdr) die("len too long");
    bbuf_append(b, hdr, (size_t)m);
    bbuf_append(b, p, n);
}

void benc_cstr(bbuf *b, const char *s)
{
    benc_bytes(b, (const unsigned char *)s, strlen(s));
}

void bdict_init(bdict *d)
{
    d->n = 0;
}

static void bdict_push(bdict *d, const char *key, bbuf value)
{
    if (d->n >= BDICT_MAX) die("too many dict entries");
    size_t klen = strlen(key);
    unsigned char *kcopy = (unsigned char *)malloc(klen ? klen : 1);
    if (!kcopy) die("out of memory");
    memcpy(kcopy, key, klen);
    d->ent[d->n].key = kcopy;
    d->ent[d->n].keylen = klen;
    d->ent[d->n].value = value;
    d->n++;
}

void bdict_add_int(bdict *d, const char *key, long long value)
{
    bbuf v;
    bbuf_init(&v);
    benc_int(&v, value);
    bdict_push(d, key, v);
}

void bdict_add_bytes(bdict *d, const char *key, const unsigned char *p, size_t n)
{
    bbuf v;
    bbuf_init(&v);
    benc_bytes(&v, p, n);
    bdict_push(d, key, v);
}

void bdict_add_cstr(bdict *d, const char *key, const char *s)
{
    bdict_add_bytes(d, key, (const unsigned char *)s, strlen(s));
}

void bdict_add_raw(bdict *d, const char *key, const unsigned char *bencoded, size_t n)
{
    bbuf v;
    bbuf_init(&v);
    bbuf_append(&v, bencoded, n);
    bdict_push(d, key, v);
}

/* Raw byte-value comparison of two keys: memcmp over the shorter length, then
 * the shorter key sorts first. This is the "sorted lexicographically by raw byte
 * value" rule of 03-conventions.md 3.2 and of BEP44 key ordering. */
static int key_less(const unsigned char *a, size_t alen,
                    const unsigned char *b, size_t blen)
{
    size_t m = alen < blen ? alen : blen;
    int c = memcmp(a, b, m);
    if (c != 0) return c < 0;
    return alen < blen;
}

void bdict_finish(bdict *d, bbuf *out)
{
    /* Insertion sort by key (n is tiny, <= BDICT_MAX). Reject a duplicate key:
     * canonical bencode dicts have each key exactly once. */
    for (int i = 1; i < d->n; i++) {
        int j = i;
        while (j > 0 && key_less(d->ent[j].key, d->ent[j].keylen,
                                 d->ent[j - 1].key, d->ent[j - 1].keylen)) {
            bdict_ent tmp = d->ent[j];
            d->ent[j] = d->ent[j - 1];
            d->ent[j - 1] = tmp;
            j--;
        }
    }
    for (int i = 1; i < d->n; i++) {
        if (d->ent[i].keylen == d->ent[i - 1].keylen &&
            memcmp(d->ent[i].key, d->ent[i - 1].key, d->ent[i].keylen) == 0) {
            die("duplicate dict key");
        }
    }

    bbuf_append(out, "d", 1);
    for (int i = 0; i < d->n; i++) {
        benc_bytes(out, d->ent[i].key, d->ent[i].keylen);
        bbuf_append(out, d->ent[i].value.data, d->ent[i].value.len);
    }
    bbuf_append(out, "e", 1);

    for (int i = 0; i < d->n; i++) {
        free(d->ent[i].key);
        bbuf_free(&d->ent[i].value);
    }
    d->n = 0;
}
