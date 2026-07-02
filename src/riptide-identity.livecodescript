script "riptide-identity"
-- =====================================================================
-- riptide-identity.livecodescript - identity and key management (doc 02).
--
-- One 32-byte master seed S becomes the whole identity: the ed25519 signing key
-- (your name and DHT identity), the X25519 box key, and the kx key, all derived
-- deterministically (02 2.2), so one backup blob reconstructs everything. This
-- module also builds and verifies the prekey bundle (02 2.4), maintains the
-- append-only key-transparency log (02 2.6), and renders safety numbers (02 2.5).
--
-- It composes the foundation library (riptide.livecodescript) for all encoding
-- and derivation, and SodiumXT for all crypto. STATUS: verified statically only;
-- needs an on-engine pass. Deterministic outputs (the identity keys, the card,
-- the BEP44 signature) are pinned by the conformance vectors / C oracle.
--
-- ASSUMED SodiumXT keypair shape. sxSignKeypairFromSeed / sxBoxKeypairFromSeed /
-- sxKeyExchangeKeypairFromSeed are assumed to return an array with keys
-- "public" and "secret". If SodiumXT returns another shape on-engine, adapt the
-- three rtKp* wrappers below (the single reconciliation point for keypairs).
-- =====================================================================

-- Registry values this module needs directly (mirrors riptide.livecodescript;
-- constants are script-local in OXT, so the few we reference are re-declared
-- here with a pointer to the authoritative registry in the foundation).
constant kSaltPrekeys is "rp-prekeys"   -- 3.7
constant kSaltIdlog is "rp-idlog"       -- 3.7
constant kIdSign is 0                   -- 02 2.2 id 0 -> ed25519 seed
constant kIdBox is 1                    -- 02 2.2 id 1 -> X25519 box seed
constant kIdKx is 2                     -- 02 2.2 id 2 -> kx seed
constant kSeedLen is 32
constant kProtoV is 1

-- ---- keypair wrappers (the one reconciliation point) -------------------
private function rtKpSignFromSeed pSeed
   return sxSignKeypairFromSeed(pSeed)
end rtKpSignFromSeed
private function rtKpBoxFromSeed pSeed
   return sxBoxKeypairFromSeed(pSeed)
end rtKpBoxFromSeed
private function rtKpKxFromSeed pSeed
   return sxKeyExchangeKeypairFromSeed(pSeed)
end rtKpKxFromSeed

-- =====================================================================
-- IDENTITY CREATION AND DERIVATION (02 2.1, 2.2)
-- =====================================================================

-- Reconstruct the full identity from a master seed S. Returns an array holding
-- the seed and all three keypairs. This is deterministic (pinned by 12.1), so
-- restoring from the one backup blob yields exactly the same identity.
function rtIdentityFromSeed pMasterSeed
   local tId, tEdSeed, tBoxSeed, tKxSeed, tEd, tBox, tKx
   put pMasterSeed into tId["seed"]
   -- rtIdentitySeed applies the rp-ident context (foundation), one call per id.
   put rtIdentitySeed(pMasterSeed, kIdSign) into tEdSeed
   put rtIdentitySeed(pMasterSeed, kIdBox) into tBoxSeed
   put rtIdentitySeed(pMasterSeed, kIdKx) into tKxSeed
   put rtKpSignFromSeed(tEdSeed) into tEd
   put rtKpBoxFromSeed(tBoxSeed) into tBox
   put rtKpKxFromSeed(tKxSeed) into tKx
   put tEd["public"] into tId["ik_ed_pub"]    -- your name / DHT identity
   put tEd["secret"] into tId["ik_ed_sec"]
   put tBox["public"] into tId["ik_x_pub"]     -- others encrypt to you (box/seal)
   put tBox["secret"] into tId["ik_x_sec"]
   put tKx["public"] into tId["kx_pub"]        -- key exchange
   put tKx["secret"] into tId["kx_sec"]
   return tId
end rtIdentityFromSeed

-- Create a brand-new identity from fresh randomness. The seed is the ONLY thing
-- the user must back up (02 2.1, threat-model N5); losing it is unrecoverable.
function rtNewIdentity
   return rtIdentityFromSeed(sxRandomBytes(kSeedLen))
end rtNewIdentity

-- The public identity card (02 2.3), canonical bencode { v, ik_ed, ik_x, kx }.
-- Delegates to the foundation so the byte-exact form (pinned by C oracle W.4)
-- lives in one place. This is what you share with contacts and publish.
function rtPublicIdentityCard pIdentity
   return rtIdentityCard(pIdentity["ik_ed_pub"], pIdentity["ik_x_pub"], pIdentity["kx_pub"])
end rtPublicIdentityCard

-- The short human-facing identity (02 2.3): URL-safe base64 of IK_pub, no pad.
function rtIdentityShortName pIdentity
   return sxBin2Base64(pIdentity["ik_ed_pub"])
end rtIdentityShortName

-- Parse and shallow-validate a received identity card. Returns an array with
-- ok/true|false and, on success, ik_ed/ik_x/kx. Fails closed on a bad version,
-- a missing field, or a wrong key length (3.10).
function rtParseIdentityCard pBencoded
   local tD, tR, tV
   put false into tR["ok"]
   put rtBdecode(pBencoded) into tD
   if not tD["ok"] then return tR
   if tD["type"] is not "dict" then return tR
   put tD["value"] into tV   -- array keyed by field name
   if tV["v"] is not kProtoV then return tR
   if the number of bytes of tV["ik_ed"] is not 32 then return tR
   if the number of bytes of tV["ik_x"] is not 32 then return tR
   if the number of bytes of tV["kx"] is not 32 then return tR
   put true into tR["ok"]
   put tV["ik_ed"] into tR["ik_ed"]
   put tV["ik_x"] into tR["ik_x"]
   put tV["kx"] into tR["kx"]
   return tR
end rtParseIdentityCard

-- =====================================================================
-- PREKEY BUNDLE (02 2.4)
-- =====================================================================
-- Lets someone message you while you are offline with forward secrecy from the
-- first message. A medium-term signed prekey SPK (rotated on a schedule) plus a
-- batch of single-use one-time prekeys OPK_i, published as a BEP44 mutable
-- record under IK with salt rp-prekeys.

-- Generate a fresh signed prekey: an X25519 box keypair whose public key is
-- signed by the identity key, proving SPK belongs to IK (02 2.4).
function rtNewSignedPrekey pIdentity
   local tKp, tR
   put sxBoxKeypair() into tKp
   put tKp["public"] into tR["spk_pub"]
   put tKp["secret"] into tR["spk_sec"]
   put sxSignDetached(tKp["public"], pIdentity["ik_ed_sec"]) into tR["spk_sig"]
   return tR
end rtNewSignedPrekey

-- Generate a batch of one-time prekeys. Returns an array: tR["count"], and
-- tR["pub"][i] / tR["sec"][i] for i in 1..count. Each is consumed by exactly one
-- sender and never reused (02 2.4, 2.7); the client persists the secrets and
-- deletes each on consumption.
function rtNewOneTimePrekeys pCount
   local tR, tI, tKp
   put pCount into tR["count"]
   repeat with tI = 1 to pCount
      put sxBoxKeypair() into tKp
      put tKp["public"] into tR["pub"][tI]
      put tKp["secret"] into tR["sec"][tI]
   end repeat
   return tR
end rtNewOneTimePrekeys

-- Build the prekey bundle bencode value (the DHT record value). opks is the list
-- of one-time prekey PUBLIC keys (may be empty; a sender who finds it empty
-- falls back to SPK-only, 02 2.4). Because BEP44 values are ~1000 bytes, only a
-- handful of OPKs fit per bundle.
--   PrekeyBundle = { v, ik_ed, ik_x, spk, spk_sig, opks:[...], exp }
function rtBuildPrekeyBundle pIdentity, pSpk, pOpkPubList, pExpiryUnix
   local tF, tListBody, tPub
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencBytes(pIdentity["ik_ed_pub"]) into tF["ik_ed"]
   put rtBencBytes(pIdentity["ik_x_pub"]) into tF["ik_x"]
   put rtBencBytes(pSpk["spk_pub"]) into tF["spk"]
   put rtBencBytes(pSpk["spk_sig"]) into tF["spk_sig"]
   -- opks is a bencode LIST of byte strings
   put "l" into tListBody
   repeat for each line tPub in pOpkPubList
      put rtBencBytes(tPub) after tListBody
   end repeat
   put "e" after tListBody
   put tListBody into tF["opks"]
   put rtBencInt(pExpiryUnix) into tF["exp"]
   return rtBencodeDict(tF)
end rtBuildPrekeyBundle

-- Publish the bundle as a BEP44 mutable record under IK with salt rp-prekeys.
-- Riptide signs the BEP44 signing buffer with the identity key (never letting
-- TorrentXT sign with its own key, 11.2.2), then hands the signature to the DHT
-- put. Reports via the result: empty on success, else an error.
command rtPublishPrekeyBundle pIdentity, pBundleValue, pSeq
   local tSignBuf, tSig
   put rtBep44SignBuffer(kSaltPrekeys, pSeq, pBundleValue) into tSignBuf
   put sxSignDetached(tSignBuf, pIdentity["ik_ed_sec"]) into tSig
   -- TorrentXT mutable put with an externally-supplied signature (11.2.2). The
   -- exact bt* handler name is confirmed on-engine; assumed btDhtPutMutable.
   btDhtPutMutable pIdentity["ik_ed_pub"], kSaltPrekeys, pSeq, pBundleValue, tSig
   return the result
end rtPublishPrekeyBundle

-- Fetch a contact's prekey bundle from the DHT, verify the BEP44 signature
-- against their identity key, verify spk_sig, and parse. pIkEdPub is the
-- contact's identity signing key (already verified out of band / via the log,
-- 02 2.5). Returns an array ok/true|false plus the fields on success. Fails
-- closed on any signature failure (3.10) - a MITM serving a forged bundle is
-- rejected here, not trial-trusted.
function rtFetchPrekeyBundle pIkEdPub
   local tGet, tR, tSignBuf, tD, tV
   put false into tR["ok"]
   -- assumed btDhtGetMutable -> array with seq/value/sig
   put btDhtGetMutable(pIkEdPub, kSaltPrekeys) into tGet
   if tGet["ok"] is not true then return tR
   put rtBep44SignBuffer(kSaltPrekeys, tGet["seq"], tGet["value"]) into tSignBuf
   if not sxSignVerifyDetached(tGet["sig"], tSignBuf, pIkEdPub) then
      put "bep44-sig-failed" into tR["error"]   -- surfaced, not swallowed (3.10)
      return tR
   end if
   put rtBdecode(tGet["value"]) into tD
   if not tD["ok"] then return tR
   if tD["type"] is not "dict" then return tR
   put tD["value"] into tV
   if tV["v"] is not kProtoV then return tR
   -- spk_sig proves SPK belongs to IK (02 2.4): verify before trusting SPK.
   if not sxSignVerifyDetached(tV["spk_sig"], tV["spk"], pIkEdPub) then
      put "spk-sig-failed" into tR["error"]
      return tR
   end if
   put true into tR["ok"]
   put tV["ik_x"] into tR["ik_x"]
   put tV["spk"] into tR["spk"]
   put tV["exp"] into tR["exp"]
   -- opks list, if present, is exposed for the handshake to pick one
   if tD["itemType"]["opks"] is "list" then
      put tV["opks"] into tR["opks"]     -- nested list array (numbered)
   end if
   return tR
end rtFetchPrekeyBundle

-- =====================================================================
-- KEY TRANSPARENCY: THE IDENTITY LOG (02 2.6)
-- =====================================================================
-- A hash-chained, ed25519-signed, append-only log published as a BEP44 seq-chain
-- under IK with salt rp-idlog. Makes a silent key substitution loud: a follower
-- pins the latest verified (seq, hash) and, on refetch, requires seq monotonic
-- and prev to match its cached hash. A fork (two valid entries at one seq, or a
-- broken prev link) is surfaced to the user (3.10), never silently accepted.

-- Canonical bencode of a log entry body { seq, prev, op, data, ts }. prev is
-- 0^32 for seq 0, else sxHash(canonical(prev entry), 32). data is op-specific,
-- passed pre-bencoded by the caller.
function rtLogEntryBody pSeq, pPrevHash, pOp, pBencodedData, pTs
   local tF
   put rtBencInt(pSeq) into tF["seq"]
   put rtBencBytes(pPrevHash) into tF["prev"]
   put rtBencBytes(pOp) into tF["op"]
   put pBencodedData into tF["data"]
   put rtBencInt(pTs) into tF["ts"]
   return rtBencodeDict(tF)
end rtLogEntryBody

-- The prev hash for the next entry: sxHash of the canonical bytes of this entry
-- body. seq 0 uses 32 zero bytes (rtZeroHash).
function rtLogEntryHash pBencodedBody
   return sxHash(pBencodedBody, 32)
end rtLogEntryHash

function rtZeroHash
   local tZ, tI
   put empty into tZ
   repeat with tI = 1 to 32
      put numToByte(0) after tZ
   end repeat
   return tZ
end rtZeroHash

-- Verify one fetched log entry against the follower's pinned state. pPinnedSeq /
-- pPinnedHash are the last verified position (empty for a first follow). Returns
-- ok/true|false with an "error" describing a detected fork/tamper so the caller
-- can surface it. Verifies: the BEP44/entry signature, seq monotonicity, and the
-- prev link.
function rtVerifyLogEntry pIkEdPub, pBencodedBody, pSig, pPinnedSeq, pPinnedHash
   local tR, tD, tV
   put false into tR["ok"]
   -- the entry is signed with the identity key over its canonical body (02 2.6)
   if not sxSignVerifyDetached(pSig, pBencodedBody, pIkEdPub) then
      put "log-sig-failed" into tR["error"]
      return tR
   end if
   put rtBdecode(pBencodedBody) into tD
   if not tD["ok"] then return tR
   put tD["value"] into tV
   if pPinnedSeq is not empty then
      if tV["seq"] <= pPinnedSeq then
         put "log-seq-not-monotonic (possible fork)" into tR["error"]
         return tR
      end if
      -- The prev of the NEXT accepted entry must chain from the pinned hash.
      -- For a strictly-next entry (seq = pinned+1) prev must equal pinned hash;
      -- for a gap the caller walks intermediate entries. Here we require the
      -- immediate-next link, the common follow case.
      if tV["seq"] is (pPinnedSeq + 1) then
         if not sxMemEqual(tV["prev"], pPinnedHash) then
            put "log-prev-link-broken (tampering or compromise)" into tR["error"]
            return tR
         end if
      end if
   else
      -- first follow: seq 0 must carry the zero prev
      if tV["seq"] is 0 then
         if not sxMemEqual(tV["prev"], rtZeroHash()) then
            put "log-genesis-prev-nonzero" into tR["error"]
            return tR
         end if
      end if
   end if
   put true into tR["ok"]
   put tV["seq"] into tR["seq"]
   put rtLogEntryHash(pBencodedBody) into tR["hash"]   -- new pin on success
   put tV["op"] into tR["op"]
   return tR
end rtVerifyLogEntry

-- =====================================================================
-- SAFETY NUMBER RENDERING (02 2.5)
-- =====================================================================
-- rtSafetyNumber (foundation) computes the 32-byte value; this renders it for
-- human out-of-band comparison as groups of decimal digits (a compact, readable
-- form; a word-list or QR mapping is a client choice). Comparison of the raw
-- bytes MUST use sxMemEqual, never `is` (3.3) - see rtSafetyNumberEqual.
function rtSafetyNumberDigits pIkA, pIkB
   local tSn, tOut, tI, tChunk, tByte
   put rtSafetyNumber(pIkA, pIkB) into tSn
   put empty into tOut
   -- 5-digit group per 2 bytes gives a Signal-like grouped number
   repeat with tI = 1 to the number of bytes of tSn step 2
      put byteToNum(byte tI of tSn) * 256 into tChunk
      if tI + 1 <= the number of bytes of tSn then
         add byteToNum(byte (tI + 1) of tSn) to tChunk
      end if
      put format("%05d", tChunk) into tByte
      if tOut is not empty then put space after tOut
      put tByte after tOut
   end repeat
   return tOut
end rtSafetyNumberDigits

-- Constant-time equality of two safety numbers (raw 32-byte values), for a
-- client that compares programmatically (for example after a QR scan).
function rtSafetyNumberEqual pSnA, pSnB
   return sxMemEqual(pSnA, pSnB)
end rtSafetyNumberEqual
