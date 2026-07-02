# CLAUDE.md

This file guides Claude Code (claude.ai/code) when working in the Riptide repository.

> **Read the spec first.** [00-overview.md](00-overview.md) (architecture),
> [01-threat-model.md](01-threat-model.md) (what we do and do not promise), and
> [03-conventions.md](03-conventions.md) (the constitution: encodings, KDF labels, envelopes, error
> model) are the source of truth for WHAT Riptide is. [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md)
> is the phased HOW and the build order. This file is the operational as-built record and the
> hard-won-lesson list, in the same spirit as the `CLAUDE.md` files in our sibling extensions
> Box2Dxt, ShowControl, TorrentXT, and SodiumXT. Most of the FFI and OXT/LCB lessons below were paid
> for in full while building those; they are carried here so we do not pay for them twice.

House style: no em-dashes (hyphens, commas, colons, parentheses). ASCII only in `.lcb` /
`.livecodescript`. Comment the *why*, densely; match the surrounding style.

## What this is

**Riptide** is a secure-communications layer for OpenXTalk (OXT) / the xTalk family. It gives xTalk
apps serverless, encrypted channels (async mailbox, live session, broadcast feed, groups, objects)
that ride the BitTorrent network. It is a **protocol**, implemented as a thin LiveCode Builder library
(public `rt*` handlers) plus livecodescript, that **composes two existing extensions**:

```
SodiumXT (sx*)   modern crypto over libsodium: identity, AEAD, secretstream, kdf, sign, box
TorrentXT (bt*)  the DHT (BEP5/BEP44), the BEP10 peer wire, swarms
      |
      +--> Riptide (rt*)   src/riptide.lcb + src/riptide-*.livecodescript
              |- examples/  riptide-demo, riptide-tests (on-engine interop harness)
```

Riptide adds **no cryptography of its own** and, ideally, **no new C shim**. The only native work it
depends on is a small set of capability gaps that land in the sibling repos
([11-capabilities-required.md](11-capabilities-required.md)), not here.

## How Riptide differs from SodiumXT and TorrentXT (read this before you assume)

Riptide is a third thing, and it inherits from BOTH siblings in ways that flip their rules back and
forth. Do not cargo-cult either one wholesale.

1. **Unlike SodiumXT, Riptide is stateful and long-lived.** SodiumXT is one call, bytes in, bytes
   out, no session. Riptide owns a **persistent, secret store**: the master seed, per-contact records
   and verified key-transparency positions, unconsumed one-time prekeys, and per-session ratchet
   chain keys and counters. State correctness (persist the advanced ratchet before treating a message
   as delivered, or a crash reuses a key) is a first-class concern here that did not exist there.
2. **Unlike SodiumXT, Riptide re-inherits TorrentXT's asynchronous, threaded world.** SodiumXT
   deleted the poll-drain architecture because libsodium owns no threads. TorrentXT does own network
   and disk threads, an alert/event queue, and a session lifecycle, and Riptide talks to that through
   the `bt*` layer. So the TorrentXT lessons about **async events, the poll/drain loop, and never
   blocking the one interpreter thread come BACK**. A DHT lookup, a peer connection, and a swarm join
   are asynchronous; Riptide is an event-driven state machine, not a sequence of blocking calls.
3. **Unlike TorrentXT, the payload IS the point and it is end-to-end encrypted before it moves.**
   Riptide's whole job is to take a user's message, seal it with SodiumXT, and hand the ciphertext to
   TorrentXT. The plaintext never crosses to a peer, a tracker, or the DHT in the clear.
4. **Riptide composes; it does not implement.** If a channel seems to need a new cryptographic
   primitive, that is a SodiumXT feature request. If it needs a new BitTorrent capability, that is a
   TorrentXT feature request ([11-capabilities-required.md](11-capabilities-required.md)). It is
   never a reason to hand-roll crypto or a peer-wire codec inside Riptide.

## The rules that make this safe

1. **Add no cryptography. Compose SodiumXT.** Every protected byte is a SodiumXT call. There is no
   Riptide cipher, no Riptide KDF, no Riptide nonce. A new primitive is an upstream feature request.
2. **The constitution is law.** [03-conventions.md](03-conventions.md) fixes the serialization
   (canonical bencode, sorted keys), the KDF label registry (8-byte contexts), the message-type
   registry, the envelope shapes, the associated-data binding, the epoch clock, and the error model.
   A channel does not invent an alternative; it extends the registries in doc 03 in the same change.
3. **Authenticate everything, fail closed, compare secrets in constant time.** Every message carries
   an authentication tag or a signature; a failed open/verify returns an error and no plaintext, never
   partial bytes (inherited from SodiumXT's `SXT_ERR_AUTH`). Compare a MAC, tag, safety number, or
   token with `sxMemEqual`, never with `is` or `=`.
4. **Never reuse a nonce, never reuse a ratchet key, never let a replay through.** Nonces are managed
   by SodiumXT (prepended, or per-chunk from a random header). Ratchet keys are single-use; persist
   the advanced chain key before delivery. Bind the epoch and sequence into the associated data
   (doc 03 section 3.5.1) and drop a record or frame whose `(channel, seq)` was already accepted.
5. **Protect the store, and be honest about what you cannot protect.** Encrypt the persistent state
   at rest (`sxPwHash` + `sxSecretBox`). A secret in a LiveCode `Data` cannot be `mlock`ed or reliably
   zeroed; minimize how long keys sit in script memory and keep bulk crypto C-side via `sxEncryptFile`.
   The security-memory boundary stops at the FFI line, exactly as SodiumXT documents.
6. **Ship the honesty.** State the non-goals (no IP anonymity by default, incomplete metadata privacy,
   no global-passive-adversary defense; [01-threat-model.md](01-threat-model.md)) to users. Do not
   present an open research item (cover-seed deniability, metadata resistance, multi-hop relay) as a
   finished guarantee.

## Commands

**Static gate for the script layer** (the only automated safety net; OXT has no headless compile):
```sh
python3 tools/check-livecodescript.py
```
Ported verbatim from SodiumXT/TorrentXT: it checks every `.lcb` and example for smart/curly quotes,
handler / control-structure / `unsafe` balance, constants-declared-before-use, and the
prefixed-token-shadow trap. A `.lcb` or `.livecodescript` change is only "done" once this passes.
**Do not claim runtime behaviour you cannot observe:** say "verified statically; needs an on-engine
pass" and let the user confirm on the OXT engine.

**Conformance vectors** (the wire-format KATs; port the SodiumXT discipline):
```sh
# builds the deterministic-derivation vectors and asserts they match 12-conformance-vectors.md
python3 tests/vectors/run.py        # or the equivalent runnable check
```

**If, and only if, Riptide adds its own C shim** (it should not; the capability shims live in the
siblings), build it under gcc ASan + UBSan exactly as SodiumXT does, and treat the sibling headers as
system headers (`-isystem`) so their warnings do not pollute `-Wall -Wextra`.

## FFI / C-ABI conventions (the gold, carried verbatim from Box2Dxt + ShowControl + TorrentXT + SodiumXT)

Riptide is mostly script over the `sx*` / `bt*` public handlers, so you will rarely write a foreign
handler here. But when you do (a helper, or the sibling-repo capability work Riptide depends on),
these rules are law. This is the single most expensive thing the family has learned. Change nothing
here without a very good reason.

- **Byte buffers cross as `Pointer` + `CInt` length. An LCB `Data` does NOT auto-bridge to a
  `void*`.** The Language Reference is explicit: "No automatic bridging from Data or String to Pointer
  exists"; a `Data` marshals as an opaque `MCDataRef`. So:
  - An **out** buffer (the shim fills it) is a raw block from the engine `<builtin>`
    `MCMemoryAllocate`, passed as a real `Pointer`. The shim returns **bytes written**, or **`-needed`**
    (negative required size) if the block was too small; the LCB layer re-allocates and retries, and
    copies the written bytes back with `MCDataCreateWithBytes`.
  - An **in** buffer passes `MCDataGetBytePtr(theData)` (the read-only pointer to the Data's own
    bytes) plus its length.
  - `<builtin>` handlers resolve by **name**, so those carry **no leading underscore**; our own
    foreign decls keep a private-name convention.
- **`MCMemoryAllocate`'s size is C `size_t`, so it marshals as `UIntSize`, NOT `CUInt`.** A 4-byte int
  into an 8-byte size slot on a 64-bit build corrupts the heap. `UIntSize` is what the proven
  htmltidy / TorrentXT / SodiumXT bindings use.
- **There is no 64-bit foreign int.** Values that can exceed 2^31 (file sizes, `opslimit`, a uint64
  KDF id, a BEP44 `seq`) cross as **decimal `ZStringUTF8`** strings, parsed in the shim.
- **Reals cross as `double`, booleans as `int` (0/1).** Exported C ABI symbols keep a stable prefix;
  never rename one once shipped (the `.lcb` `binds to` strings reference it by name; a rename is a
  silent bind failure at load).
- **Never RETURN a bridged C string** (`ZStringUTF8` / `NativeCString` / `WString`) from a foreign
  handler: the engine adopts the returned pointer and later `free()`s it, so a static or
  library-owned return is `free()`-on-static, heap corruption on the first call. Fill a caller buffer
  and return length / `-needed` instead (the SodiumXT string entry points show the pattern).
- **Pass a null pointer only through an `optional Pointer`** parameter; a plain `Pointer` rejects
  `nothing`.
- **Bump the ABI version on any ABI change**, and have the `.lcb` `checkABI()` throw a clear
  "reinstall the extension" error on skew instead of corrupting memory on first use. Expose every
  length constant from the shim as a function; never hardcode 24/32/16 in LCB.
- **`textEncode` / `textDecode` are NOT available to an LCB module** (they are livecodescript only), so
  bytes cross as `Data` and a String is built from filled bytes with `MCStringCreateWithBytes`.

## Handles and long-lived state

- **Stateful C primitives** (should any live in a Riptide shim) use a **generation-tagged handle
  table** exactly as SodiumXT's secretstream / multipart-hash tables do: positive 32-bit ints, `0`
  invalid, a stale or recycled handle is a clean no-op / error and never a crash, with an explicit,
  idempotent free (there is no deterministic LCB unload hook). Riptide mostly holds SodiumXT's handles
  (secretstream sessions) rather than making its own; free what you open (for example on `closeStack`).
- **Riptide's own long-lived state is script-side and persistent** (section 4 of the plan): the
  master seed, contacts, prekeys, and per-session ratchet chain keys and counters. Persist the
  advanced ratchet state atomically before treating a message as delivered, or a crash reuses a
  message key. Encrypt the store at rest.

## The asynchronous, event-driven model (re-inherited from TorrentXT)

OXT runs script, the FFI, and rendering on ONE interpreted thread, and TorrentXT's engine owns
background network and disk threads that surface **asynchronous events** (a DHT lookup completes, a
peer connects, a swarm has peers, a BEP10 message arrives). Therefore:

- **Never block the interpreter thread on the network.** A rendezvous lookup, a handshake, and a
  record put/get are asynchronous. Riptide is a set of **state machines** driven by TorrentXT events,
  not a straight line of blocking calls. Follow the TorrentXT poll/drain and callback discipline; do
  not busy-wait.
- **Keep status updates at <= ~4 Hz** and keep any blocking crypto (a big `sxPwHash` at SENSITIVE
  limits, a whole-file `sxEncryptFile`) off the moment-to-moment UI path or clearly flagged as a
  pause, exactly as SodiumXT's performance playbook warns.
- **Time and epochs:** the epoch clock (doc 03 section 3.9) uses wall-clock time; check adjacent
  epochs for drift. Do not assume two peers' clocks agree exactly.

## LiveCodeScript / LCB / OXT gotchas (carried; OXT is stricter than LiveCode)

1. **No smart/curly quotes** (U+201C/201D/2018/2019) anywhere, even in a comment or string: they fail
   OXT compilation. ASCII `"` and `'` only. The static checker enforces zero.
2. **Avoid names whose stem shadows an engine token even when prefixed.** The nastiest case is a
   prefixed name whose full spelling IS a reserved token: `tExt` (t + "Ext") is literally `text`, so
   xTalk evaluates it as the keyword, not a variable. It compiles and silently misbehaves. The checker
   flags any `t/p/s/k`-prefixed name that lowercases to a reserved word; use a different stem.
3. **Prefix conventions:** `t` handler-local, `p` parameter, `s` script/module-local, `k` constant.
   Public API `rtPascalCase`; C ABI (if any) `rtx_snake_case`.
4. **Constants must be literal and declared before first use** (OXT resolves a constant by lexical
   position; a forward reference silently evaluates to nothing).
5. **`unsafe ... end unsafe` brackets every foreign call** in LCB; keep all declarations at the **top**
   of a handler (a nested `local` has broken whole-script compilation).
6. **Commands report via `the result`; functions return a value.** Match the API shapes in the spec.
7. **`itemDelimiter` / `lineDelimiter` are global mutable state**: set them immediately before use.
8. **`is a <type>` only accepts** number / integer / boolean / point / rect / date / color. There is
   **no `is a string`**. To sniff bytes, check length / content, not a type.
9. **A whole `.livecodescript` compiles as a unit:** a syntax error in one handler breaks the whole
   script, and the engine may report it at the first line it tries to run. When "the demo broke" at an
   unrelated line, suspect a compile error elsewhere in the same script, and re-run the static gate.
10. **After the bundled native libraries change, reinstall the extension and restart the engine** so
    the `.lcb` and the native library reload as a matched pair; a stale half-updated install makes the
    first `sx*` / `bt*` call fail via the `checkABI()` guard. (Learned the hard way in SodiumXT.)

## The single-threaded performance playbook (earned in OXT, adapted for "encrypted payload + network")

- **One FFI round-trip per logical crypto operation.** Encrypt a buffer in one `sx*` call, not one
  per 16 bytes; the out-buffer retry costs at most one extra call.
- **Do not pull a large payload through script.** For anything that does not comfortably fit in memory
  twice, use SodiumXT's C-side file helpers (`sxEncryptFile` / `sxDecryptFile`) and carry it as an
  encrypted torrent (doc 09), so the bytes never enter a LiveCode `Data`.
- **Reuse a persistent out-buffer** in any hot path; rebuilding an N-byte `Data` every call is O(N)
  interpreter work.
- **Crypto is blocking, the network is not.** A big `sxPwHash` or file encrypt pauses the UI; a DHT
  lookup does not (it is an event). Keep the first off the UI beat; drive the second by callbacks.

## Protocol and crypto correctness rules (the part a comms protocol most easily gets wrong)

- **Follow the constitution byte for byte.** Canonical bencode with sorted keys; the exact BEP44
  signing buffer (doc 03 section 3.7); the exact associated-data binding (`bencode({e,q,t})`). A
  one-byte encoding difference is a silent interop break, and for the BEP44 signature it is a broken
  signature.
- **Conformance vectors are mandatory.** The deterministic derivations have fixed known answers
  ([12-conformance-vectors.md](12-conformance-vectors.md)); assert them in a runnable test that fails
  on a libsodium bump. Round-trip tests alone hide a byte-mangling bug.
- **Negative tests are the security tests.** Tamper a byte -> open fails; replay -> dropped; wrong key
  -> fails; stale epoch -> rejected; forged signature -> rejected; a fork in the key-transparency log
  -> surfaced to the user, never silently accepted.
- **Verify keys at first contact** (safety number or the key-transparency log, doc 02); a rung-3
  adversary that controls the DHT lookup can otherwise attempt a MITM.
- **Never present an open problem as solved.** Metadata privacy, cover-seed deniability, group forward
  secrecy, and multi-hop relay are tracked in [13-open-questions.md](13-open-questions.md); ship them
  labeled for what they are.

## Git / workflow

- Develop on a per-task branch (e.g. `claude/...`); commit there, open a **draft PR** if none exists.
  Do not push to `main` without explicit permission.
- A `.lcb` / `.livecodescript` change is "done" once `tools/check-livecodescript.py` passes and it has
  had (or is flagged as needing) an on-engine pass. A protocol change is "done" once its conformance
  vectors pass and a two-instance interop round-trip works on-engine.
- A change that touches a sibling's C shim bumps that sibling's ABI version and `checkABI()` in the
  same change, upstream, and refreshes the committed native binary and its `MANIFEST.sha256` (the
  SodiumXT model).
- **No em-dashes** in committed prose or docs (house style). Use hyphens, commas, colons, parentheses.
- **Match the surrounding style:** comment the *why*, densely, as the siblings do.

## As-built record (the operational truth, updated as we build)

This section is the running as-built log the top of this file promises. It states what exists, how
each piece is verified, and the open items, so no one has to reconstruct it from the diff.

### What exists now (Phase 0 foundation + Phase 1 identity)

```
src/
  riptide.livecodescript            foundation: the constitution made executable
  riptide-identity.livecodescript   doc 02: seed, derivation, card, prekeys, key-transparency log
  riptide-store.livecodescript      plan 4: encrypted-at-rest store + the ratchet-persist discipline
  riptide-rendezvous.livecodescript doc 04: rid/pid/mid/coverId, the announce/getPeers dance, hello
  riptide-session.livecodescript    doc 05: X3DH handshake, secretstream tunnel, rekey, cover-seed
  riptide-transport.livecodescript  the single bt* bridge: DHT/BEP44/rp1/phantom over TorrentXT v10
examples/
  riptide-tests.livecodescript      on-engine self-test: asserts the frozen KATs through sx*, + negatives
  riptide-demo.livecodescript       the Phase 0 vertical-slice driver (phantom swarm, async poll loop)
tests/vectors/
  vectors.c                         the 12.x derivation KATs (pre-existing; passes on libsodium 1.0.18)
  rt_bencode.{c,h}                  reference canonical-bencode encoder (the oracle, NOT shipped)
  wire_vectors.c                    byte-exact KATs: AD binding, BEP44 sign buffer (vs 12.6), id card
  run.py                            builds + runs both C programs; the runnable conformance gate
.github/workflows/ci.yml            the static gate + conformance vectors on every push
```

### How each piece is verified (be precise about this; do not overclaim)

- **RUN-verified here (real, executable):** `tests/vectors/run.py` -> both C programs green against
  libsodium 1.0.18. This pins the deterministic wire format: all 12.x derivations, the AD binding
  bencode, the BEP44 signing buffer (cross-checked to the 12.6 signature by BUILDING the buffer and
  signing it, not by freezing a string), and the identity-card canonical bencode. The oracle already
  caught two hand-encoding errors (a dropped dict-close `e`, a length prefix written in hex not
  decimal), which is exactly why it exists.
- **Statically verified only (`tools/check-livecodescript.py` passes):** every `.livecodescript`.
  There is no headless OpenXTalk here, so this is the ceiling for the script layer. Say "verified
  statically; needs an on-engine pass," never "works."
- **The bridge between the two:** `examples/riptide-tests.livecodescript` asserts the SAME frozen
  answers as the C oracle, but through the `rt*`/`sx*` handlers. Running it on-engine is what promotes
  the foundation from "static" to "on-engine verified," and it is the reconciliation vehicle for the
  assumed `sx*` shapes (a mismatch fails a KAT and names the call to fix).

### Architecture decisions taken (and why), for the next builder

- **Implemented in `.livecodescript`, not `.lcb` (yet).** The plan names `riptide.lcb` as the public
  library. Two constraints pushed the first cut to script: (a) the sibling `sx*`/`bt*` LCB module
  names and exact signatures are not visible from this repo, so calling them from LCB is a guess; (b)
  byte-wrangling (bencode) is idiomatic and higher-confidence in livecodescript (`numToByte`,
  `binaryEncode`, byte chunks) than in unverifiable LCB byte ops. The `riptide.lcb` public-API/ABI
  wrapper is a deferred refactor to do once the sibling modules can be linked on-engine. This is
  noted, not hidden.
- **All `sx*` calls are funnelled and documented** (the "-- sx bridge --" note in the foundation, the
  `rtKp*` wrappers in identity, the `rtDh*` helpers in session), so an on-engine signature mismatch is
  a one-place fix, not a scatter hunt. The assumed shapes come from doc 11's handler table and the
  12.x vectors.
- **All `bt*` (TorrentXT) calls are funnelled through ONE module** (`riptide-transport.livecodescript`),
  for the same reason. Reconciled against the shipped TorrentXT ABI v10: `btDhtGetPeers`/`btDhtAnnounce`
  on a bare id, `btDhtBep44SignBuf`/`btDhtPutSigned`/`btDhtGetMutable` (external signing hook),
  `btRp1Enable`/`btRp1SetToken`/`btRp1Send`/`btRp1Poll`, `btAddInfohash` (phantom swarm), and
  `btStartSession`/`btPoll`/`btStopSession`. Two shapes drove real changes: ids cross as **40-hex
  strings** (raw 20-byte ids are `sxBin2Hex`'d only at this boundary), and the DHT is **asynchronous**
  (a get is "start a query" now + "match the `dhtGetPeers`/`dhtMutableItem` poll event" later, never a
  blocking return), so `rtRendezvousDiscover` split into `...Start` + `rtRendezvousCollect` and the
  prekey fetch into `...Start` + `...FromItem`. BEP44 signing stays in SodiumXT: we sign the exact
  buffer `btDhtBep44SignBuf` returns and hand only the detached signature to `btDhtPutSigned`, so the
  identity key never enters TorrentXT (11.2.2 option a).
- **Constants are script-local in OXT**, so channel modules call the foundation's *functions* for all
  encoding/derivation and mirror only the handful of salts/types they name directly (each with a
  pointer back to the authoritative registry in `riptide.livecodescript`).

### Open items to resolve on-engine / upstream (the honest punch-list)

- **Upstream TorrentXT blockers: RESOLVED in TorrentXT ABI v10.** All four Phase 0 capabilities
  landed - arbitrary-id DHT announce/get_peers (11.2.1), BEP10 `rp1` custom extension messages
  (11.2.3), peer/connection events (11.2.5), phantom-swarm mode (11.2.6) - plus the BEP44 external
  signing hook (11.2.2). The bridge (`riptide-transport.livecodescript`) is reconciled to the shipped
  handler signatures and the async poll-drain model. What remains is the ON-ENGINE run: load SodiumXT
  + TorrentXT + Riptide on the OXT engine and drive two instances through `riptide-demo` (the crypto is
  pinned by the vectors; the transport path is static-clean and needs the live confirmation). Two
  reconciliation points are flagged inline for that pass: (a) the poll-event representation (a "List of
  Arrays", iterated with `for each element` in the transport matchers), and (b) the BEP44 value
  convention (`rtRunTransportReconcile` in the self-test asserts `btDhtBep44SignBuf` bencodes a raw
  `Data` value into the same buffer Riptide signs; a mismatch means records must be pre-bencoded before
  the put, a one-place fix in `rtPublishPrekeyBundle`).
- **crypto_kx rx/tx pairing (flag for the maintainer to pin in doc 05/12).** The X3DH DH values and
  the source-2 pairwise secret depend on which crypto_kx session-key half each side takes. libsodium
  guarantees `client_rx == server_tx`, so this implementation takes that provably-equal pairing
  (initiator/client takes `rx`, responder/server takes `tx`); a literal reading of the 05 5.3.2
  snippet ("put tRx into DH1" on both sides) would diverge. There is no KAT for these (12.7 validates
  them by "both sides agree"), so the on-engine two-instance handshake is the gate. Worth a one-line
  clarification in doc 05 and a pinned handshake vector in doc 12.
- **Assumed `sx*` script shapes** (keypair-as-array, secretstream handle/tag arrays, kx rx/tx array):
  confirm against the SodiumXT script API and adjust the bridge wrappers if they differ.
- **The `.lcb` public-API/ABI wrapper and packaging** (`package-extension.py` is ported and ready) are
  deferred until the siblings can be linked on-engine.
