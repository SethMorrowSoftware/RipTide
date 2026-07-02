/*
 * wire_vectors.c - Riptide canonical-encoding known-answer tests.
 *
 * Complements vectors.c (which pins the KDF / hash / ed25519 DERIVATIONS of
 * 12-conformance-vectors.md) by pinning the byte-exact SERIALIZATIONS that the
 * constitution (03-conventions.md) fixes and that every interoperable
 * implementation must reproduce exactly:
 *
 *   - the associated-data binding  ad = bencode({e,q,t})            (3.5.1)
 *   - the BEP44 mutable signing buffer                              (3.7)
 *   - the canonical bencode of the identity card                   (02, 2.3)
 *
 * The BEP44 case is the load-bearing one: instead of hard-coding the signing
 * string, we BUILD it with the same helper the LCB layer mirrors and then sign
 * it with the identity key of 12.1, asserting the signature equals the value
 * pinned in 12.6. That proves the builder emits the right bytes AND that they
 * round-trip through ed25519 the way a real DHT will verify.
 *
 * These frozen answers are also the ones the on-engine self-test
 * (examples/riptide-tests.livecodescript) asserts through the sx* handlers, so
 * the C path and the OXT path are pinned to one truth (tests/vectors/README.md).
 *
 * Build:  cc -O2 wire_vectors.c rt_bencode.c -lsodium -o wire_vectors && ./wire_vectors
 */
#include "rt_bencode.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0;

static void check_hex(const char *label, const unsigned char *got, size_t n,
                      const char *expect_hex)
{
    char hex[1024];
    if (n * 2 + 1 > sizeof hex) { printf("  FAIL - %s (too long)\n", label); g_fail++; return; }
    sodium_bin2hex(hex, sizeof hex, got, n);
    if (strcmp(hex, expect_hex) == 0) {
        printf("  ok   - %s\n", label);
    } else {
        printf("  FAIL - %s\n         got      %s\n         expected %s\n",
               label, hex, expect_hex);
        g_fail++;
    }
}

/* Compare an emitted buffer to an expected ASCII string, and show both readably
 * (these buffers are printable ASCII by construction). */
static void check_ascii(const char *label, const bbuf *got, const char *expect)
{
    size_t elen = strlen(expect);
    if (got->len == elen && memcmp(got->data, expect, elen) == 0) {
        printf("  ok   - %s  (\"%.*s\")\n", label, (int)got->len, got->data);
    } else {
        printf("  FAIL - %s\n         got      \"%.*s\"\n         expected \"%s\"\n",
               label, (int)got->len, got->data, expect);
        g_fail++;
    }
}

/* --- the two constructions the LCB layer must mirror byte for byte --- */

/* AD binding (3.5.1): ad = bencode({ e: epoch, q: seq, t: type }). Keys sort
 * e < q < t by raw byte value, so the encoder emits them in that order. */
static void build_ad(bbuf *out, long long epoch, long long seq, long long type)
{
    bdict d;
    bdict_init(&d);
    bdict_add_int(&d, "e", epoch);
    bdict_add_int(&d, "q", seq);
    bdict_add_int(&d, "t", type);
    bdict_finish(&d, out);
}

/* BEP44 mutable signing buffer (3.7): the concatenation
 *   [4:salt <bencoded salt>]  3:seq i<seq>e  1:v <bencoded value>
 * The salt segment is omitted when there is no salt (BEP44). The value is
 * appended AS ITS BENCODED FORM: in real Riptide use the record value is itself
 * a canonical-bencode envelope dict (d...e), so its bencoded form is those very
 * bytes, NOT re-wrapped as a byte string. The caller passes the already-bencoded
 * value. (For the 12.6 vector the value is the string "hi", whose bencoded form
 * is the 4 bytes "2:hi".) */
static void build_bep44_signbuf(bbuf *out, const unsigned char *salt, size_t saltlen,
                                long long seq, const unsigned char *bval, size_t bvlen)
{
    if (saltlen > 0) {
        benc_cstr(out, "salt");             /* 4:salt   */
        benc_bytes(out, salt, saltlen);     /* <len>:<salt> */
    }
    benc_cstr(out, "seq");                  /* 3:seq    */
    benc_int(out, seq);                     /* i<seq>e  */
    benc_cstr(out, "v");                    /* 1:v      */
    bbuf_append(out, bval, bvlen);          /* raw bencoded value */
}

int main(void)
{
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }
    printf("Riptide wire vectors (against libsodium %s)\n", sodium_version_string());

    /* ---- W.1  AD binding, using the rendezvous-hello example (04, 4.3.1):
     *          epoch = 471000 (as in 12.2), q = 0, t = 0x04 (rendezvous-hello). */
    {
        bbuf ad;
        bbuf_init(&ad);
        build_ad(&ad, 471000, 0, 4);
        check_ascii("W.1 AD binding {e:471000,q:0,t:4}", &ad, "d1:ei471000e1:qi0e1:ti4ee");
        bbuf_free(&ad);
    }

    /* ---- W.2  AD binding for a mailbox data message: epoch, a nonzero seq, and
     *          t = 0x10 (mailbox message), to exercise multi-digit seq/type. */
    {
        bbuf ad;
        bbuf_init(&ad);
        build_ad(&ad, 471000, 42, 16);   /* 0x10 = 16 */
        check_ascii("W.2 AD binding {e:471000,q:42,t:16}", &ad, "d1:ei471000e1:qi42e1:ti16ee");
        bbuf_free(&ad);
    }

    /* ---- W.3  BEP44 signing buffer + signature, cross-checked against 12.6.
     *          Identity from 12.1 (seed S = 00..1f), salt rp-prekeys, seq 1,
     *          value = string "hi". */
    {
        unsigned char S[32];
        for (int i = 0; i < 32; i++) S[i] = (unsigned char)i;
        unsigned char edSeed[32];
        crypto_kdf_derive_from_key(edSeed, sizeof edSeed, 0, "rp-ident", S);
        unsigned char ikpub[crypto_sign_PUBLICKEYBYTES], iksk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_seed_keypair(ikpub, iksk, edSeed);

        bbuf sb;
        bbuf_init(&sb);
        build_bep44_signbuf(&sb, (const unsigned char *)"rp-prekeys", 10, 1,
                            (const unsigned char *)"2:hi", 4);
        check_ascii("W.3 BEP44 sign buffer", &sb, "4:salt10:rp-prekeys3:seqi1e1:v2:hi");

        unsigned char sig[crypto_sign_BYTES];
        crypto_sign_detached(sig, NULL, sb.data, sb.len, iksk);
        check_hex("W.3 BEP44 signature (== 12.6)", sig, sizeof sig,
                  "86c843ec4cc2495e025e949dd72658ef01556dbbfb1f5d9b474b5957dbcb26a2"
                  "3497efe40f594387cc4f037075669efa4c42cb57c007eb0bddaa24934f3f740b");
        if (crypto_sign_verify_detached(sig, sb.data, sb.len, ikpub) != 0) {
            printf("  FAIL - W.3 BEP44 signature self-verify\n"); g_fail++;
        } else {
            printf("  ok   - W.3 BEP44 signature self-verifies against IK_pub\n");
        }
        bbuf_free(&sb);
    }

    /* ---- W.3b salt-less BEP44 signing buffer (3.7 / mainline BEP44): with no
     *          salt the entire "4:salt<salt>" segment is omitted. The mailbox's
     *          portable default uses salt-less mutable puts, so this form must be
     *          pinned too (audit finding). seq 1, value "hi". */
    {
        bbuf sb;
        bbuf_init(&sb);
        build_bep44_signbuf(&sb, NULL, 0, 1, (const unsigned char *)"2:hi", 4);
        check_ascii("W.3b BEP44 sign buffer (salt-less)", &sb, "3:seqi1e1:v2:hi");
        bbuf_free(&sb);
    }

    /* ---- W.4  Canonical bencode of the identity card (02, 2.3): the CONSTITUTION
     *          (3.2) makes v AND t mandatory on every structured record and 3.6
     *          reserves 0x01 identity-card, so the card is
     *          { v:1, t:1, ik_ed: IK_pub, ik_x: IK_x_pub, kx: KX_pub } with the
     *          keys of 12.1. Keys sort ik_ed < ik_x < kx < t < v by raw CONTENT
     *          byte value (the BEP rule: a shorter key that is a prefix sorts
     *          first). This vector pins the mixed-length-key sort the audit flagged
     *          as ambiguous, and pins the t-field decision. */
    {
        unsigned char S[32];
        for (int i = 0; i < 32; i++) S[i] = (unsigned char)i;
        unsigned char edSeed[32], boxSeed[32], kxSeed[32];
        crypto_kdf_derive_from_key(edSeed, sizeof edSeed, 0, "rp-ident", S);
        crypto_kdf_derive_from_key(boxSeed, sizeof boxSeed, 1, "rp-ident", S);
        crypto_kdf_derive_from_key(kxSeed, sizeof kxSeed, 2, "rp-ident", S);
        unsigned char ikpub[crypto_sign_PUBLICKEYBYTES], iksk[crypto_sign_SECRETKEYBYTES];
        unsigned char ikx_pk[crypto_box_PUBLICKEYBYTES], ikx_sk[crypto_box_SECRETKEYBYTES];
        unsigned char kx_pk[crypto_kx_PUBLICKEYBYTES], kx_sk[crypto_kx_SECRETKEYBYTES];
        crypto_sign_seed_keypair(ikpub, iksk, edSeed);
        crypto_box_seed_keypair(ikx_pk, ikx_sk, boxSeed);
        crypto_kx_seed_keypair(kx_pk, kx_sk, kxSeed);

        bdict d;
        bdict_init(&d);
        bdict_add_int(&d, "v", 1);
        bdict_add_int(&d, "t", 1);   /* 0x01 identity-card (3.6); mandatory per 3.2 */
        bdict_add_bytes(&d, "ik_ed", ikpub, sizeof ikpub);
        bdict_add_bytes(&d, "ik_x", ikx_pk, sizeof ikx_pk);
        bdict_add_bytes(&d, "kx", kx_pk, sizeof kx_pk);
        bbuf card;
        bbuf_init(&card);
        bdict_finish(&d, &card);
        printf("       (identity card hex: ");
        { char h[512]; sodium_bin2hex(h, sizeof h, card.data, card.len); printf("%s)\n", h); }
        check_hex("W.4 identity card bencode {v,t,ik_ed,ik_x,kx}", card.data, card.len,
                  "64353a696b5f656433323a672e8e0b259627f15c772ec0d61f15cd786ce2bc7244549255f9d6cfaac300b2343a696b5f7833323a5b9d094b6c0de5c16b3605cffd6d056144384855f82d02c352c5cffd3b60bf65323a6b7833323a4a9789d887a6dcb2246f1a03833dab4c6c77c57633caef004190ba5f990a3d35313a74693165313a7669316565");
        bbuf_free(&card);
    }

    printf("-------------------\n");
    if (g_fail == 0) { printf("ALL WIRE VECTORS MATCH\n"); return 0; }
    printf("%d WIRE VECTOR(S) FAILED\n", g_fail); return 1;
}
