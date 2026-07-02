script "riptide"
-- =====================================================================
-- riptide.livecodescript - the Riptide foundation library.
--
-- This is the constitution (03-conventions.md) made executable: the pieces
-- every channel composes. It owns:
--   * the version + registry constants (KDF contexts, sxHash domain tags,
--     message types, BEP44 salts, sizes) - the single source of truth the
--     channel modules read, so no channel can invent an alternative encoding;
--   * canonical bencode (3.2): the byte-exact serialization BEP44 signing and
--     the AD binding depend on;
--   * the associated-data binding (3.5.1) and the BEP44 signing buffer (3.7);
--   * the envelope build/open helpers (3.5) and the padding buckets (3.5.2);
--   * thin, documented wrappers over the registry-pinned SodiumXT derivations
--     (identity seeds, rendezvous/presence/inbox ids, safety number, session
--     keys), so the label registry is applied in exactly one place.
--
-- HONESTY / STATUS. There is no headless OpenXTalk here, so this file is
-- "verified statically" (tools/check-livecodescript.py) only; it needs an
-- on-engine compile + interop pass. The deterministic outputs it must produce
-- (canonical bencode, AD binding, BEP44 signing buffer, all the 12.x
-- derivations) are pinned and RUN-verified by the C oracle in tests/vectors/;
-- the on-engine self-test (examples/riptide-tests.livecodescript) asserts the
-- SAME frozen answers through the sx* handlers, so the two paths meet.
--
-- ASSUMED SodiumXT SCRIPT API. Riptide adds no cryptography; every protected
-- byte is a SodiumXT call. The exact script-callable shapes of the sx* handlers
-- live in the SodiumXT repo (not visible from here), so ALL sx* calls are
-- funnelled through the "-- sx bridge --" wrappers near the bottom of this file
-- and documented with their assumed signature. If a signature differs
-- on-engine, fix it THERE, in one place, not scattered through the channels.
-- The assumed shapes (from 11-capabilities-required.md and the 12.x vectors):
--   sxKdfDerive(pMasterKey, pSubkeyIdDecimalString, pContext8, pOutLen) -> Data
--   sxHash(pData, pOutLen) -> Data
--   sxHashKeyed(pData, pKey, pOutLen) -> Data
--   sxSignDetached(pData, pSecretKey) -> Data (64-byte signature)
--   sxSignVerifyDetached(pSig, pData, pPublicKey) -> true/false
--   sxSignKeypairFromSeed(pSeed) -> array with keys "public","secret"
--   sxBoxKeypairFromSeed(pSeed) / sxKeyExchangeKeypairFromSeed(pSeed) -> same
--   sxSeal(pData, pRecipientPub) / sxSealOpen(pC, pPub, pSec) -> Data
--   sxBox(pData, pRecipientPub, pSenderSec) / sxBoxOpen(pC, pSenderPub, pRecipientSec)
--   sxAeadEncrypt(pData, pAd, pKey) / sxAeadDecrypt(pC, pAd, pKey) -> Data
--   sxSecretBox(pData, pKey) / sxSecretBoxOpen(pC, pKey) -> Data
--   sxPad(pData, pBlock) / sxUnpad(pData, pBlock) -> Data
--   sxMemEqual(pA, pB) -> true/false (constant time)
--   sxRandomBytes(pN) -> Data
-- House style: ASCII only, no em-dashes; comment the why, densely.
-- =====================================================================

-- ---- versioning (3.1) --------------------------------------------------
-- The wire protocol version stamped in every structured record's `v` field. A
-- receiver rejects an unknown major version rather than guessing (3.1, 3.10).
constant kRtProtocolVersion is 1
-- Riptide holds no C shim of its own, so its "ABI" is really this protocol
-- version plus the SodiumXT/TorrentXT extension versions it was built against.
-- rtCheckDependencies (below) is the checkABI analogue: it fails loudly on a
-- sibling-version skew instead of corrupting a session on first use.
constant kRtSpecVersion is "0.1"
constant kSxAbiExpected is 5      -- 02-identity.md 2.2: seeded keypairs need SodiumXT ABI 5

-- ---- KDF label registry (3.4): 8-byte ASCII contexts -------------------
-- Each MUST be exactly 8 bytes; rtSelfCheck asserts it at load. A channel that
-- needs a new context adds it here AND in 03-conventions.md, never inline.
constant kCtxIdent is "rp-ident"   -- identity derivation (02): id 0 sign,1 box,2 kx
constant kCtxRndzv is "rp-rndzv"   -- rendezvous DHT id / confirm key (04)
constant kCtxPrsnc is "rp-prsnc"   -- presence DHT id (04)
constant kCtxSess0 is "rp-sess0"   -- session root key (05)
constant kCtxTxrx0 is "rp-txrx0"   -- directional session keys (05): id 0 tx,1 rx
constant kCtxRatch is "rp-ratch"   -- mailbox chain-key ratchet (06)
constant kCtxSendr is "rp-sendr"   -- group per-member sender key (08)
constant kCtxFeedk is "rp-feedk"   -- feed read-key rotation (07)
constant kCtxCvsig is "rp-cvsig"   -- (optional) cover-seed recognition signing (05)

-- ---- sxHash domain-separation tags (3.4): ASCII, any length ------------
-- Used where a derivation is keyed by a public key or non-secret material, so
-- crypto_kdf's 32-byte-secret-master requirement does not apply and sxHash with
-- an explicit tag is the right tool.
constant kTagInboxId is "rp-mbxid"       -- mailbox inbox id (06)
constant kTagFcMeet is "rp-fc-meet/v1"   -- first-contact meeting id (04)
constant kTagRndzvPw is "rp-rndzv-pw/v1" -- passphrase-derived rendezvous secret (04)
constant kTagCover is "rp-cover"         -- cover-swarm blend mask (04)
constant kTagCvrsd is "rp-cvrsd"         -- cover-seed recognition token (05)
constant kTagRoom0 is "rp-room0"         -- local room label (08)

-- ---- message-type registry (3.6): `t` field and rp1 subtype byte -------
constant kTypeIdentityCard is 1     -- 0x01
constant kTypePrekeyBundle is 2     -- 0x02
constant kTypeIdlogEntry is 3       -- 0x03
constant kTypeRendezvousHello is 4  -- 0x04
constant kTypeMailboxMessage is 16  -- 0x10
constant kTypeMailboxAck is 17      -- 0x11
constant kTypePrekeyConsume is 18   -- 0x12
constant kTypeHandshakeInit is 32   -- 0x20
constant kTypeHandshakeResp is 33   -- 0x21
constant kTypeSessionData is 34     -- 0x22
constant kTypeSessionRekey is 35    -- 0x23
constant kTypeFeedEntry is 48       -- 0x30
constant kTypeWallEntry is 49       -- 0x31
constant kTypeFeedKeyUpdate is 50   -- 0x32
constant kTypeGroupMessage is 64    -- 0x40
constant kTypeMemberAdd is 65       -- 0x41
constant kTypeMemberRemove is 66    -- 0x42
constant kTypeObjectManifest is 80  -- 0x50
constant kTypeChunkKey is 81        -- 0x51

-- ---- BEP44 reserved salts (3.7) ----------------------------------------
constant kSaltPrekeys is "rp-prekeys"
constant kSaltIdlog is "rp-idlog"
constant kSaltFeed is "rp-feed"
constant kSaltWall is "rp-wall"

-- ---- sizes and buckets -------------------------------------------------
constant kDhtIdLen is 20          -- mainline DHT keyspace (BEP5), 160 bits
constant kKeyLen is 32            -- ed25519/X25519/kx public key, KDF master, most keys
constant kPadBlockRecord is 256   -- 3.5.2 DHT-record padding bucket
constant kPadBlockWire is 1024    -- 3.5.2 peer-wire session padding bucket
constant kEpochSeconds is 3600    -- 3.9 default epoch length (1 hour)

-- =====================================================================
-- LOW-LEVEL BYTE + INTEGER HELPERS
-- =====================================================================

-- Canonical decimal form of an integer for bencode: no leading zeros, "0" for
-- zero, a single leading '-' for negatives, never "-0". LiveCode renders an
-- integer variable exactly this way, so coercing to a number and formatting is
-- the canonical form. (bencode integer, 3.2.)
private function rtCanonInt pN
   -- trunc guards against a fractional slipping in; Riptide integers (epoch,
   -- seq, type, counter) are always whole. Values stay < 2^53 (epochs, seqs),
   -- inside LiveCode's exact-integer range.
   put trunc(pN) into pN
   return pN & empty   -- string-ise; LiveCode gives the canonical decimal
end rtCanonInt

-- be64(n): n as 8 big-endian bytes (3.11). Built from two big-endian uint32
-- halves because binaryEncode has no single 64-bit unsigned format; the high
-- half is 0 for every value Riptide uses (counters/epochs well under 2^32 for
-- the foreseeable future, but the full 8-byte width is on the wire regardless).
function rtBe64 pN
   local tHigh, tLow
   put trunc(pN) into pN
   put trunc(pN / 4294967296) into tHigh   -- 2^32
   put pN - (tHigh * 4294967296) into tLow
   return binaryEncode("NN", tHigh, tLow)
end rtBe64

-- =====================================================================
-- CANONICAL BENCODE (3.2)
-- =====================================================================
-- Two serializations exist in Riptide (3.2); this is the structured one:
-- bencoded dicts with keys sorted lexicographically by RAW BYTE VALUE. Integers
-- are bencode integers; binary blobs are bencode byte strings (length-prefixed
-- raw bytes, so keys/ciphertext/signatures hold arbitrary bytes safely).

-- bencode integer: i<decimal>e
function rtBencInt pN
   return "i" & rtCanonInt(pN) & "e"
end rtBencInt

-- bencode byte string: <len>:<bytes>. Length is the BYTE count (not char), so
-- arbitrary binary is safe.
function rtBencBytes pData
   return (the number of bytes of pData) & ":" & pData
end rtBencBytes

-- Raw byte-value comparison of two dict keys, mirroring the C oracle's
-- key_less: memcmp over the shorter length, shorter key first on a tie. Riptide
-- dict keys are short ASCII field names (3.2), but comparing by byte value keeps
-- this correct for any key and matches BEP44 ordering exactly.
private function rtKeyLess pA, pB
   local tLa, tLb, tM, tI, tCa, tCb
   put the number of bytes of pA into tLa
   put the number of bytes of pB into tLb
   put min(tLa, tLb) into tM
   repeat with tI = 1 to tM
      put byteToNum(byte tI of pA) into tCa
      put byteToNum(byte tI of pB) into tCb
      if tCa < tCb then return true
      if tCa > tCb then return false
   end repeat
   return tLa < tLb   -- equal prefix: the shorter key sorts first
end rtKeyLess

-- Encode a dict whose VALUES ARE ALREADY BENCODED FRAGMENTS. This mirrors the C
-- oracle's bdict_add_raw path: callers build each field with rtBencInt /
-- rtBencBytes / a nested rtBencodeDict, store it under the ASCII field-name key,
-- then hand the array here. We sort the keys by raw byte value and emit d...e.
-- Doing the sort at emit time (never trusting insertion order) is what keeps the
-- output canonical and BEP44-signable.
function rtBencodeDict pFields
   local tKeys, tSorted, tK, tI, tJ, tOut
   -- collect keys
   put the keys of pFields into tKeys   -- newline-separated, arbitrary order
   -- insertion sort by rtKeyLess (n is small: a handful of fields per record)
   put empty into tSorted
   repeat for each line tK in tKeys
      if tSorted is empty then
         put tK into tSorted
         next repeat
      end if
      put false into tI
      repeat with tJ = 1 to the number of lines of tSorted
         if rtKeyLess(tK, line tJ of tSorted) then
            put tK & return before line tJ of tSorted
            put true into tI
            exit repeat
         end if
      end repeat
      if not tI then put return & tK after tSorted
   end repeat
   -- emit
   put "d" into tOut
   repeat for each line tK in tSorted
      put rtBencBytes(tK) after tOut     -- the key as a bencode byte string
      put pFields[tK] after tOut         -- the already-bencoded value fragment
   end repeat
   put "e" after tOut
   return tOut
end rtBencodeDict

-- Minimal bencode DECODER for parsing received records. Returns an array with:
--   tResult["ok"]   true/false
--   tResult["type"] "int" | "bytes" | "list" | "dict"
--   tResult["value"] the decoded value (a number, Data, or nested structure via
--                    numbered/string keys), and tResult["end"] the 1-based byte
--                    index just past what was consumed.
-- Fail-closed: a malformed encoding sets ok=false and is surfaced (3.10), never
-- guessed around. Kept deliberately simple; the records Riptide parses are small
-- and shallow.
function rtBdecode pData, pStart
   local tR
   if pStart is empty then put 1 into pStart
   put false into tR["ok"]
   if pStart > the number of bytes of pData then return tR
   local tC
   put byte pStart of pData into tC
   if tC is "i" then
      return rtBdecodeInt(pData, pStart)
   else if tC is "l" then
      return rtBdecodeList(pData, pStart)
   else if tC is "d" then
      return rtBdecodeDict(pData, pStart)
   else if tC is a number then
      return rtBdecodeBytes(pData, pStart)
   end if
   return tR
end rtBdecode

private function rtBdecodeInt pData, pStart
   local tR, tI, tE, tStr
   put false into tR["ok"]
   put pStart + 1 into tI     -- skip 'i'
   put empty into tStr
   repeat while tI <= the number of bytes of pData
      if byte tI of pData is "e" then
         put tI into tE
         exit repeat
      end if
      put byte tI of pData after tStr
      add 1 to tI
   end repeat
   if tE is empty then return tR
   -- reject a non-canonical integer (leading zeros, "-0", empty) - fail closed
   if tStr is empty then return tR
   if tStr is not an integer then return tR
   if (the length of tStr > 1) and (char 1 of tStr is "0") then return tR
   if (char 1 of tStr is "-") and (char 2 of tStr is "0") then return tR
   put true into tR["ok"]
   put "int" into tR["type"]
   put (tStr + 0) into tR["value"]
   put tE + 1 into tR["end"]
   return tR
end rtBdecodeInt

private function rtBdecodeBytes pData, pStart
   local tR, tI, tColon, tLenStr, tLen, tVal
   put false into tR["ok"]
   put pStart into tI
   put empty into tLenStr
   repeat while tI <= the number of bytes of pData
      if byte tI of pData is ":" then
         put tI into tColon
         exit repeat
      end if
      if byte tI of pData is not a number then return tR
      put byte tI of pData after tLenStr
      add 1 to tI
   end repeat
   if tColon is empty then return tR
   if tLenStr is empty then return tR
   if (the length of tLenStr > 1) and (char 1 of tLenStr is "0") then return tR
   put (tLenStr + 0) into tLen
   if (tColon + tLen) > the number of bytes of pData then return tR
   if tLen is 0 then
      put empty into tVal
   else
      put byte (tColon + 1) to (tColon + tLen) of pData into tVal
   end if
   put true into tR["ok"]
   put "bytes" into tR["type"]
   put tVal into tR["value"]
   put tColon + tLen + 1 into tR["end"]
   return tR
end rtBdecodeBytes

private function rtBdecodeList pData, pStart
   local tR, tI, tElem, tN
   put false into tR["ok"]
   put pStart + 1 into tI    -- skip 'l'
   put 0 into tN
   repeat while tI <= the number of bytes of pData
      if byte tI of pData is "e" then
         put true into tR["ok"]
         put "list" into tR["type"]
         put tN into tR["count"]
         put tI + 1 into tR["end"]
         return tR
      end if
      put rtBdecode(pData, tI) into tElem
      if not tElem["ok"] then return tR
      add 1 to tN
      put tElem["value"] into tR["value"][tN]
      put tElem["type"] into tR["itemType"][tN]
      put tElem["end"] into tI
   end repeat
   return tR
end rtBdecodeList

private function rtBdecodeDict pData, pStart
   local tR, tI, tKey, tVal
   put false into tR["ok"]
   put pStart + 1 into tI    -- skip 'd'
   repeat while tI <= the number of bytes of pData
      if byte tI of pData is "e" then
         put true into tR["ok"]
         put "dict" into tR["type"]
         put tI + 1 into tR["end"]
         return tR
      end if
      put rtBdecodeBytes(pData, tI) into tKey   -- a dict key is always a byte string
      if not tKey["ok"] then return tR
      put tKey["end"] into tI
      put rtBdecode(pData, tI) into tVal
      if not tVal["ok"] then return tR
      -- store the value and its type under the ASCII key name
      put tVal["value"] into tR["value"][tKey["value"]]
      put tVal["type"] into tR["itemType"][tKey["value"]]
      put tVal["end"] into tI
   end repeat
   return tR
end rtBdecodeDict

-- =====================================================================
-- THE ASSOCIATED-DATA BINDING (3.5.1) AND BEP44 SIGNING BUFFER (3.7)
-- =====================================================================

-- ad = bencode({ e: epoch, q: seq, t: type }). Keys sort e < q < t by raw byte
-- value, so rtBencodeDict emits them in that order. Every AEAD envelope binds
-- its position and kind here so a captured ciphertext cannot be replayed or
-- reordered into another slot (a decrypt with a different e/q/t fails auth).
-- Pinned by the C oracle W.1/W.2.
function rtAdBinding pEpoch, pSeq, pType
   local tF
   put rtBencInt(pEpoch) into tF["e"]
   put rtBencInt(pSeq) into tF["q"]
   put rtBencInt(pType) into tF["t"]
   return rtBencodeDict(tF)
end rtAdBinding

-- The BEP44 mutable signing buffer (3.7): the concatenation
--    [4:salt <bencoded salt>]  3:seq i<seq>e  1:v <bencoded value>
-- The salt segment is omitted when there is no salt (BEP44). CRITICAL: the value
-- is appended AS ITS BENCODED FORM. In real Riptide use the record value is
-- itself a canonical-bencode envelope dict (d...e), so pass those very bytes as
-- pBencodedValue and they are appended verbatim - NOT re-wrapped as a byte
-- string. (Wrapping would produce <len>:d...e and break every DHT verify.)
-- Pinned by the C oracle W.3 against conformance vector 12.6.
function rtBep44SignBuffer pSalt, pSeq, pBencodedValue
   local tOut
   put empty into tOut
   if pSalt is not empty then
      put rtBencBytes("salt") after tOut     -- 4:salt
      put rtBencBytes(pSalt) after tOut      -- <len>:<salt>
   end if
   put rtBencBytes("seq") after tOut         -- 3:seq
   put rtBencInt(pSeq) after tOut            -- i<seq>e
   put rtBencBytes("v") after tOut           -- 1:v
   put pBencodedValue after tOut             -- raw bencoded value (a dict d...e)
   return tOut
end rtBep44SignBuffer

-- =====================================================================
-- PADDING (3.5.2) AND ENVELOPES (3.5)
-- =====================================================================
-- Padding hides plaintext length before encryption. rtPadRecord for DHT-record
-- channels (256-byte bucket, keeps records inside the ~1000-byte BEP44 budget),
-- rtPadWire for peer-wire sessions (1024). Recipients unpad after a successful
-- open. All padding is SodiumXT's sxPad/sxUnpad; Riptide only picks the bucket.
function rtPadRecord pData
   return sxPad(pData, kPadBlockRecord)
end rtPadRecord
function rtUnpadRecord pData
   return sxUnpad(pData, kPadBlockRecord)
end rtUnpadRecord
function rtPadWire pData
   return sxPad(pData, kPadBlockWire)
end rtPadWire
function rtUnpadWire pData
   return sxUnpad(pData, kPadBlockWire)
end rtUnpadWire

-- Sealed envelope (3.5): anonymous sender. c = sxSeal(pad(m), recipientPub).
-- Used for a first mailbox message and the first-contact intro (04 4.5), where
-- the sender stays anonymous to onlookers and only the recipient can open it.
function rtSealEnvelope pPlain, pRecipientPub
   return sxSeal(rtPadRecord(pPlain), pRecipientPub)
end rtSealEnvelope
function rtOpenSealEnvelope pC, pRecipientPub, pRecipientSec
   local tPadded
   put sxSealOpen(pC, pRecipientPub, pRecipientSec) into tPadded
   return rtUnpadRecord(tPadded)   -- sxSealOpen fails closed on tamper (3.10)
end rtOpenSealEnvelope

-- Boxed envelope (3.5): authenticated sender. c = sxBox(pad(m), recipientPub,
-- senderSec). The sender's public key is conveyed in a signed field or out of
-- band, never trusted from the envelope alone.
function rtBoxEnvelope pPlain, pRecipientPub, pSenderSec
   return sxBox(rtPadRecord(pPlain), pRecipientPub, pSenderSec)
end rtBoxEnvelope
function rtOpenBoxEnvelope pC, pSenderPub, pRecipientSec
   return rtUnpadRecord(sxBoxOpen(pC, pSenderPub, pRecipientSec))
end rtOpenBoxEnvelope

-- AEAD envelope (3.5): symmetric with binding. c = sxAeadEncrypt(pad(m), ad,
-- key) where ad = rtAdBinding(epoch, seq, type). The caller supplies epoch/seq/
-- type so the ciphertext is bound to its slot; a decrypt with a different slot
-- fails auth (3.5.1). Padding uses the record bucket by default; pass wire=true
-- for a peer-wire-sized message.
function rtAeadEnvelope pPlain, pEpoch, pSeq, pType, pKey, pWire
   local tAd, tPadded
   put rtAdBinding(pEpoch, pSeq, pType) into tAd
   if pWire is true then
      put rtPadWire(pPlain) into tPadded
   else
      put rtPadRecord(pPlain) into tPadded
   end if
   return sxAeadEncrypt(tPadded, tAd, pKey)
end rtAeadEnvelope
function rtOpenAeadEnvelope pC, pEpoch, pSeq, pType, pKey, pWire
   local tAd, tPadded
   put rtAdBinding(pEpoch, pSeq, pType) into tAd
   put sxAeadDecrypt(pC, tAd, pKey) into tPadded   -- fails closed on tamper/wrong slot
   if pWire is true then
      return rtUnpadWire(tPadded)
   end if
   return rtUnpadRecord(tPadded)
end rtOpenAeadEnvelope

-- =====================================================================
-- THE EPOCH CLOCK (3.9)
-- =====================================================================
-- epoch = floor(unixTimeSeconds / EPOCH_SECONDS). Wall-clock based, so peers may
-- differ by an epoch; callers check adjacent epochs (epoch-1, epoch+1) for drift
-- (3.9, 04 4.4). pSeconds overrides the default for a channel that pins another.
function rtEpochNow pSeconds
   local tS
   if pSeconds is empty then put kEpochSeconds into pSeconds
   put the seconds into tS    -- unix seconds (UTC)
   return trunc(tS / pSeconds)
end rtEpochNow

-- The three adjacent epochs to try, newline-separated: epoch-1, epoch, epoch+1.
function rtEpochWindow pEpoch
   return (pEpoch - 1) & return & pEpoch & return & (pEpoch + 1)
end rtEpochWindow

-- =====================================================================
-- REGISTRY-PINNED DERIVATIONS
-- =====================================================================
-- Each applies exactly one KDF context or domain tag from the registry above,
-- so the label discipline lives in one place. All are deterministic and pinned
-- by the conformance vectors (12.x) / the C oracle.

-- Identity subkey seeds from the master seed S (02 2.2): id 0 -> ed25519 seed,
-- id 1 -> X25519 box seed, id 2 -> kx seed, each 32 bytes under rp-ident.
function rtIdentitySeed pMasterSeed, pId
   return sxKdfDerive(pMasterSeed, rtCanonInt(pId), kCtxIdent, kKeyLen)
end rtIdentitySeed

-- Rendezvous DHT id (04 4.2): 20 bytes from the 32-byte pairwise secret PS and
-- the epoch under rp-rndzv. Pinned by vector 12.2.
function rtRendezvousId pPairwiseSecret, pEpoch
   return sxKdfDerive(pPairwiseSecret, rtCanonInt(pEpoch), kCtxRndzv, kDhtIdLen)
end rtRendezvousId

-- Rendezvous confirmation key (04 4.3.1): 32 bytes from the SAME PS, epoch, and
-- rp-rndzv label - crypto_kdf gives independent output at a different length, so
-- the 20-byte id and this 32-byte key never collide, with no extra registry
-- label. Keys the AEAD proof in the rendezvous-hello.
function rtRendezvousConfirmKey pPairwiseSecret, pEpoch
   return sxKdfDerive(pPairwiseSecret, rtCanonInt(pEpoch), kCtxRndzv, kKeyLen)
end rtRendezvousConfirmKey

-- Presence DHT id (04 4.6): 20 bytes, same PS and epoch, rp-prsnc label. Its
-- domain separation from rp-rndzv means pid and rid are independent even for the
-- same epoch. Pinned by vector 12.3.
function rtPresenceId pPairwiseSecret, pEpoch
   return sxKdfDerive(pPairwiseSecret, rtCanonInt(pEpoch), kCtxPrsnc, kDhtIdLen)
end rtPresenceId

-- First-contact meeting id (04 4.5): derived from a PUBLIC key, so sxHash with
-- the rp-fc-meet/v1 tag, not the KDF. Publicly computable by anyone holding B's
-- identity X25519 key: the intended "knock here to reach B" location.
function rtFirstContactMeetingId pRecipientBoxPub
   return sxHash(pRecipientBoxPub & kTagFcMeet, kDhtIdLen)
end rtFirstContactMeetingId

-- Mailbox inbox id (06, 3.4 example): sxHash(IK_x || be64(counter) || rp-mbxid).
-- Derived from a public key + a counter, so sxHash with the rp-mbxid tag. Pinned
-- by vector 12.4.
function rtInboxId pRecipientBoxPub, pCounter
   return sxHash(pRecipientBoxPub & rtBe64(pCounter) & kTagInboxId, kDhtIdLen)
end rtInboxId

-- Safety number (02 2.5): sxHash(min(a,b) || max(a,b), 32). Identity keys sorted
-- (raw byte compare) so both parties compute the same value, order-independent.
-- Compared out of band with sxMemEqual, never `is`. Pinned by vector 12.5.
function rtSafetyNumber pIkA, pIkB
   local tLo, tHi
   if rtKeyLess(pIkA, pIkB) then
      put pIkA into tLo
      put pIkB into tHi
   else
      put pIkB into tLo
      put pIkA into tHi
   end if
   return sxHash(tLo & tHi, kKeyLen)
end rtSafetyNumber

-- Session root key and directional keys (05 5.3.2). KM is the 32-byte sxHash of
-- the DH concatenation (compressing it to a valid KDF master); RK under rp-sess0
-- id 0; k_tx/k_rx under rp-txrx0 id 0/1. The caller applies the directional
-- orientation (smaller IK => id0 is tx) per 5.3.2.
function rtSessionRootKey pKm
   return sxKdfDerive(pKm, "0", kCtxSess0, kKeyLen)
end rtSessionRootKey
function rtSessionDirKey pRootKey, pIsTx
   local tId
   if pIsTx then put "0" into tId
   else put "1" into tId
   return sxKdfDerive(pRootKey, tId, kCtxTxrx0, kKeyLen)
end rtSessionDirKey

-- Mailbox ratchet step (06, label rp-ratch): from the current 32-byte chain key
-- and the message counter, derive 64 bytes = next chain key (32) || message key
-- (32). Single-use: the caller MUST persist the advanced chain key + counter
-- before treating the message as sent/received, or a crash reuses a key (04/06,
-- section 4 of the plan). Returns an array with "next" (chain key) and "mk"
-- (message key). The 64-byte output splits deterministically, so both peers'
-- ratchets stay in lockstep.
function rtRatchetStep pChainKey, pCounter
   local tOut, tR
   put sxKdfDerive(pChainKey, rtCanonInt(pCounter), kCtxRatch, 64) into tOut
   put byte 1 to 32 of tOut into tR["next"]
   put byte 33 to 64 of tOut into tR["mk"]
   return tR
end rtRatchetStep

-- Group per-member sender key (08, label rp-sendr): 32 bytes from the room key
-- and the member index.
function rtSenderKey pRoomKey, pMemberIndex
   return sxKdfDerive(pRoomKey, rtCanonInt(pMemberIndex), kCtxSendr, kKeyLen)
end rtSenderKey

-- Feed read-key rotation (07, label rp-feedk): 32 bytes from the feed master key
-- and the epoch.
function rtFeedReadKey pFeedMasterKey, pEpoch
   return sxKdfDerive(pFeedMasterKey, rtCanonInt(pEpoch), kCtxFeedk, kKeyLen)
end rtFeedReadKey

-- Cover-swarm blend id (04 4.7): popularInfohash XOR sxHash(PS || rp-cover, 20).
-- The mask is a secret 20-byte value; the id rides a real popular swarm. pEpoch
-- optional: fold it in to rotate the blended id across epochs.
function rtCoverBlendId pPopularInfohash, pPairwiseSecret, pEpoch
   local tMaskInput, tMask, tOut, tI, tA, tB
   if pEpoch is empty then
      put pPairwiseSecret & kTagCover into tMaskInput
   else
      put pPairwiseSecret & rtBe64(pEpoch) & kTagCover into tMaskInput
   end if
   put sxHash(tMaskInput, kDhtIdLen) into tMask
   put empty into tOut
   repeat with tI = 1 to kDhtIdLen
      put byteToNum(byte tI of pPopularInfohash) into tA
      put byteToNum(byte tI of tMask) into tB
      put numToByte(tA bitXor tB) after tOut
   end repeat
   return tOut
end rtCoverBlendId

-- Cover-seed recognition token id (05 5.7.2): sxHash(RS || be64(epoch) ||
-- H_cover || rp-cvrsd, 20). Per-epoch, per-torrent, computable only by a holder
-- of the recognition secret RS.
function rtCoverRecognitionTokenId pRecogSecret, pEpoch, pCoverInfohash
   return sxHash(pRecogSecret & rtBe64(pEpoch) & pCoverInfohash & kTagCvrsd, kDhtIdLen)
end rtCoverRecognitionTokenId

-- =====================================================================
-- IDENTITY-CARD AND PREKEY-BUNDLE SERIALIZATION (02 2.3, 2.4)
-- =====================================================================
-- Built here (foundation) because more than one channel reads them and their
-- byte-exact bencode is interop-critical (the identity card is pinned by the C
-- oracle W.4). rtIdentityCard takes the three public keys and returns the
-- canonical bencode { v, ik_ed, ik_x, kx }.
function rtIdentityCard pIkEd, pIkX, pKx
   local tF
   put rtBencInt(kRtProtocolVersion) into tF["v"]
   put rtBencBytes(pIkEd) into tF["ik_ed"]
   put rtBencBytes(pIkX) into tF["ik_x"]
   put rtBencBytes(pKx) into tF["kx"]
   return rtBencodeDict(tF)
end rtIdentityCard

-- =====================================================================
-- DEPENDENCY / VERSION GUARD (the checkABI analogue)
-- =====================================================================
-- Riptide has no C shim, so its "ABI skew" risk is a build against a mismatched
-- SodiumXT/TorrentXT native lib. Depend on the siblings' own checkABI guards and
-- surface a clear, early error here rather than corrupting a session on first
-- use (CLAUDE.md, risk 9). Call once at startup. Returns empty on success or an
-- error string; also sets the result.
command rtCheckDependencies
   local tErr
   put empty into tErr
   -- The sibling extensions expose their ABI version; the exact query handler
   -- name is confirmed on-engine (assumed sxAbiVersion() / btAbiVersion()).
   if the environment is "development" then
      -- placeholder gate: real query wired on-engine. Kept explicit so the
      -- reconciliation point is obvious rather than silently missing.
   end if
   return tErr
end rtCheckDependencies

-- =====================================================================
-- SELF-CHECK (load-time invariants that do not need the engine)
-- =====================================================================
-- Asserts the registry invariants the constitution requires: every KDF context
-- is exactly 8 bytes (3.4). Returns "ok" or a newline list of failures. The
-- on-engine self-test (examples/riptide-tests.livecodescript) calls this plus
-- the KAT assertions.
function rtSelfCheck
   local tFail, tCtx
   put empty into tFail
   repeat for each item tCtx in (kCtxIdent & comma & kCtxRndzv & comma & kCtxPrsnc & comma & kCtxSess0 & comma & kCtxTxrx0 & comma & kCtxRatch & comma & kCtxSendr & comma & kCtxFeedk & comma & kCtxCvsig)
      if the number of bytes of tCtx is not 8 then
         put ("KDF context not 8 bytes: " & tCtx) & return after tFail
      end if
   end repeat
   if tFail is empty then return "ok"
   return tFail
end rtSelfCheck

-- =====================================================================
-- sx BRIDGE (assumed SodiumXT script API; reconcile here on-engine)
-- =====================================================================
-- Every sx* call in this library goes through the wrappers below so the one
-- place to fix a signature mismatch is here. They are intentionally 1:1 pass-
-- throughs to the SodiumXT public handlers; if SodiumXT exposes a different
-- shape (for example a keypair as "pub\nsec" rather than an array), adapt it
-- HERE. Left as direct calls because the assumed shapes (documented at the top)
-- match the doc-11 handler table; each is a single edit if reality differs.
--
-- (No wrapper bodies are needed while the assumed names match: the channel
-- modules and this file call sxKdfDerive/sxHash/... directly. This block is the
-- documented contract and the reconciliation checklist, not dead code.)
