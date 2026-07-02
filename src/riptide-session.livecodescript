script "riptide-session"
-- =====================================================================
-- riptide-session.livecodescript - the pairwise live session (doc 05).
--
-- Turns a first contact into a keyed, forward-secret conversation over the peer
-- wire: an X3DH-style handshake yielding a session root key RK and two
-- directional keys, two secretstream streams (one per direction) carrying every
-- application message as an rp1 0x22 frame, rekey for forward secrecy over the
-- session lifetime, and the cover-seed recognition that hides the session inside
-- a real lawful torrent. This is the Phase 0 vertical slice's session half.
--
-- Composes the foundation (session-key derivation, AD binding, bencode) and
-- SodiumXT (crypto_kx, secretstream, ed25519). Peer-wire ops are TorrentXT (bt*/
-- PW.*), funnelled through the rtPw* wrappers; they are the upstream-blocked
-- capabilities (11.2.3 rp1, 11.2.5 connection events, 11.2.6 phantom swarm).
--
-- STATUS: verified statically only; needs an on-engine pass. The X3DH DH values
-- and session keys are validated by the "both sides agree" property (12.7), not
-- a KAT, so the on-engine self-test's two-instance round-trip is the real gate.
--
-- CRYPTO NOTE (reconciliation point). Each X3DH DHi is a crypto_kx agreement
-- with the initiator as client and the responder as server (05 5.3.2). libsodium
-- guarantees client_rx == server_tx, so BOTH sides take that guaranteed-equal
-- half: the initiator takes its kx "rx", the responder takes its kx "tx". (The
-- spec snippet writes "put tRx into DH1" on both sides; taken literally with
-- libsodium's rx/tx labeling the two halves differ, so this file takes the
-- provably-equal pairing and the on-engine round-trip confirms it. Flagged for
-- the maintainer to pin in doc 05/12.)
-- =====================================================================

constant kProtoV is 1
constant kTypeInit is 32     -- 0x20 handshake-init
constant kTypeResp is 33     -- 0x21 handshake-resp / header
constant kTypeData is 34     -- 0x22 session data
constant kTypeRekey is 35    -- 0x23 rekey
constant kKeyLen is 32
constant kFpLen is 16        -- prekey fingerprint length (05 5.3.3: sxHash(...,16))
constant kKeepaliveSeconds is 30
constant kKeepaliveTimeout is 90

-- =====================================================================
-- THE X3DH AGREEMENT (5.3.2)
-- =====================================================================

-- The guaranteed-equal shared half for one DH: the client takes rx, the server
-- takes tx (both == firstHalf; see the crypto note). pRole is "client" for the
-- initiator, "server" for the responder.
private function rtDhShared pRole, pMyPub, pMySec, pTheirPub
   local tSess
   if pRole is "client" then
      put sxKeyExchangeClient(pMyPub, pMySec, pTheirPub) into tSess
      return tSess["rx"]
   else
      put sxKeyExchangeServer(pMyPub, pMySec, pTheirPub) into tSess
      return tSess["tx"]
   end if
end rtDhShared

-- Derive RK, k_tx, k_rx from the four DH values and the two identity keys. The
-- directional orientation (5.3.2): the peer with the smaller IK_pub treats id 0
-- as k_tx and id 1 as k_rx; the other swaps, so each side has a distinct send
-- key with no extra round trip and no reused key across directions.
private function rtSessionKeysFromDh pDhm, pMyIk, pPeerIk
   local tKm, tRk, tId0, tId1, tR
   put sxHash(pDhm, kKeyLen) into tKm        -- compress DHM to a 32-byte KDF master
   put rtSessionRootKey(tKm) into tRk        -- rp-sess0 id 0
   put rtSessionDirKey(tRk, true) into tId0  -- rp-txrx0 id 0
   put rtSessionDirKey(tRk, false) into tId1 -- rp-txrx0 id 1
   put tRk into tR["rk"]
   if rtKeyLess(pMyIk, pPeerIk) then
      put tId0 into tR["k_tx"]
      put tId1 into tR["k_rx"]
   else
      put tId1 into tR["k_tx"]
      put tId0 into tR["k_rx"]
   end if
   return tR
end rtSessionKeysFromDh

-- =====================================================================
-- HANDSHAKE, INITIATOR SIDE (5.3.3 steps 1-4, 7-8)
-- =====================================================================

-- Step 1-4: A builds the handshake-init. pBundleB is the verified prekey bundle
-- (from rtFetchPrekeyBundle: ik_x, spk, optional opks). pOpkPub is the chosen
-- one-time prekey public key (empty for SPK-only). Returns a session array
-- carrying the frame to send plus the derived keys and the ephemeral secret
-- (which the caller zeroes after step 8). Fails closed if spk_sig is unverified
-- (the caller verifies it during fetch, 2.4).
function rtHandshakeInit pIdentityA, pPeerIkEd, pBundleB, pOpkPub, pEpoch
   local tEk, tDh1, tDh2, tDh3, tDh4, tDhm, tKeys
   local tSpkFp, tOpkFp, tF, tSignBody, tSig, tBody, tS
   put sxBoxKeypair() into tEk                          -- fresh ephemeral (FS source)
   -- DH1..DH4, A is always the client (5.3.2)
   put rtDhShared("client", pIdentityA["ik_x_pub"], pIdentityA["ik_x_sec"], pBundleB["spk"]) into tDh1
   put rtDhShared("client", tEk["public"], tEk["secret"], pBundleB["ik_x"]) into tDh2
   put rtDhShared("client", tEk["public"], tEk["secret"], pBundleB["spk"]) into tDh3
   put tDh1 & tDh2 & tDh3 into tDhm
   put sxHash(pBundleB["spk"], kFpLen) into tSpkFp
   if pOpkPub is not empty then
      put rtDhShared("client", tEk["public"], tEk["secret"], pOpkPub) into tDh4
      put tDhm & tDh4 into tDhm
      put sxHash(pOpkPub, kFpLen) into tOpkFp
   else
      put empty into tOpkFp
   end if
   put rtSessionKeysFromDh(tDhm, pIdentityA["ik_ed_pub"], pPeerIkEd) into tKeys
   -- build the init dict; g signs the canonical bencode of all other fields
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencInt(kTypeInit) into tF["t"]
   put rtBencBytes(pIdentityA["ik_ed_pub"]) into tF["ik"]
   put rtBencBytes(pIdentityA["ik_x_pub"]) into tF["ix"]
   put rtBencBytes(tEk["public"]) into tF["ek"]
   put rtBencBytes(tSpkFp) into tF["sp"]
   put rtBencBytes(tOpkFp) into tF["op"]     -- empty byte string when SPK-only
   put rtBencInt(pEpoch) into tF["ep"]
   put rtBencodeDict(tF) into tSignBody       -- bencode(dict without g)
   put sxSignDetached(tSignBody, pIdentityA["ik_ed_sec"]) into tSig
   put rtBencBytes(tSig) into tF["g"]
   put rtBencodeDict(tF) into tBody
   -- assemble the session record the caller keeps across the round trip
   put "handshaking" into tS["state"]
   put "initiator" into tS["role"]
   put pPeerIkEd into tS["peer_ik"]
   put pEpoch into tS["epoch"]
   put tKeys["rk"] into tS["rk"]
   put tKeys["k_tx"] into tS["k_tx"]
   put tKeys["k_rx"] into tS["k_rx"]
   put tEk["secret"] into tS["ek_sec"]        -- zeroed after step 8
   put tEk["public"] into tS["init_ek"]       -- kept to recompute the key-confirm MAC (step 7)
   put pIdentityA["ik_ed_pub"] into tS["my_ik"]
   put numToByte(kTypeInit) & tBody into tS["frame"]
   return tS
end rtHandshakeInit

-- Step 7-8: A processes the handshake-resp, verifies B, inits its pull stream on
-- B's header, then inits its own push stream and returns the header frame to
-- send (a second 0x21). Returns ok/true|false and the updated session with the
-- stream handles; on success the session is established after B accepts the
-- header (step 9). Fails closed on a bad signature or a key-confirmation
-- mismatch (5.3.4, 3.10).
function rtHandshakeFinishInit pSession, pRespBody
   local tD, tV, tSignBody, tExpectAc, tPush, tHeaderF, tS
   put pSession into tS
   put false into tS["ok"]
   put rtBdecode(pRespBody) into tD
   if not tD["ok"] then return tS
   put tD["value"] into tV
   if tV["t"] is not kTypeResp then return tS
   -- verify g against B's identity key (which A holds and verified, 2.5)
   put rtRespSignBody(tV) into tSignBody
   if not sxSignVerifyDetached(tV["g"], tSignBody, pSession["peer_ik"]) then
      put "resp-sig-failed" into tS["error"]
      return tS
   end if
   -- verify the key-confirmation MAC ac: proves B derived the same RK (5.3.4)
   put rtKeyConfirmMac(pSession) into tExpectAc
   if not sxMemEqual(tV["ac"], tExpectAc) then
      put "key-confirm-failed (wrong key / MITM / tamper)" into tS["error"]
      return tS
   end if
   -- init A's pull stream on B's header (A now decrypts B's stream)
   put sxSecretStreamInitPull(pSession["k_rx"], tV["hd"]) into tS["h_pull"]
   -- init A's own push stream, and build the header frame to send (step 8)
   put sxSecretStreamInitPush(pSession["k_tx"]) into tPush
   put tPush["handle"] into tS["h_push"]
   put rtHeaderFrame(tPush["header"]) into tHeaderF
   put tHeaderF into tS["header_frame"]
   put "established" into tS["state"]
   -- the ephemeral secret has done its job; zero and drop it (5.3.3 note, FS)
   put empty into tS["ek_sec"]
   put true into tS["ok"]
   return tS
end rtHandshakeFinishInit

-- =====================================================================
-- HANDSHAKE, RESPONDER SIDE (5.3.3 steps 5-6, 9)
-- =====================================================================

-- Step 5-6: B processes a handshake-init. pMyPrekeys resolves the SPK/OPK named
-- by the fingerprints; it is an array with spk_pub/spk_sec and, keyed by OPK
-- fingerprint hex, opk secrets. B verifies g, reconstructs the DHs as the
-- server, derives keys, builds the handshake-resp, and inits its push stream.
-- Returns ok/true|false, the resp frame, and the session (with h_push set).
-- Fails closed on version/epoch/signature/consumed-OPK errors (5.3.5, 3.10).
function rtHandshakeAcceptInit pIdentityB, pInitBody, pMyEpoch, pMyPrekeys
   local tD, tV, tSignBody, tSpkSec, tOpkSec, tOpkFpHex
   local tDh1, tDh2, tDh3, tDh4, tDhm, tKeys, tPush
   local tRespF, tAc, tS
   put false into tS["ok"]
   put rtBdecode(pInitBody) into tD
   if not tD["ok"] then return tS
   put tD["value"] into tV
   if tV["v"] is not kProtoV then
      put "bad-version" into tS["error"]
      return tS
   end if
   if tV["t"] is not kTypeInit then return tS
   -- epoch window check (5.3.3 step 5, 3.9 drift)
   if abs(tV["ep"] - pMyEpoch) > 1 then
      put "epoch-out-of-window" into tS["error"]
      return tS
   end if
   -- verify g binds the whole init to A's identity key (stops forgery/replay)
   put rtInitSignBody(tV) into tSignBody
   if not sxSignVerifyDetached(tV["g"], tSignBody, tV["ik"]) then
      put "init-sig-failed" into tS["error"]
      return tS
   end if
   -- resolve the named signed prekey (must match B's current SPK fingerprint)
   if not sxMemEqual(tV["sp"], sxHash(pMyPrekeys["spk_pub"], kFpLen)) then
      put "unknown-spk" into tS["error"]
      return tS
   end if
   put pMyPrekeys["spk_sec"] into tSpkSec
   -- reconstruct DH1..DH3 as the server (B holds SPK for DH1/DH3, IK_x for DH2)
   put rtDhShared("server", pMyPrekeys["spk_pub"], tSpkSec, tV["ix"]) into tDh1
   put rtDhShared("server", pIdentityB["ik_x_pub"], pIdentityB["ik_x_sec"], tV["ek"]) into tDh2
   put rtDhShared("server", pMyPrekeys["spk_pub"], tSpkSec, tV["ek"]) into tDh3
   put tDh1 & tDh2 & tDh3 into tDhm
   -- DH4 only if the init named a one-time prekey; that OPK must be unconsumed
   if tV["op"] is not empty then
      put sxBin2Hex(tV["op"]) into tOpkFpHex
      put pMyPrekeys["opk"][tOpkFpHex] into tOpkSec
      if tOpkSec is empty then
         put "opk-unknown-or-consumed" into tS["error"]   -- replay defense (5.3.5)
         return tS
      end if
      -- the matching OPK public is needed as our server pub; the caller supplies
      -- it alongside the secret (opk_pub map). Reconstruct DH4.
      put rtDhShared("server", pMyPrekeys["opk_pub"][tOpkFpHex], tOpkSec, tV["ek"]) into tDh4
      put tDhm & tDh4 into tDhm
      -- signal the caller to CONSUME this OPK atomically (rtStoreConsumeOpk)
      put tOpkFpHex into tS["consume_opk"]
   end if
   put rtSessionKeysFromDh(tDhm, pIdentityB["ik_ed_pub"], tV["ik"]) into tKeys
   -- init B's push stream (5.3.3 step 6) and build the resp
   put sxSecretStreamInitPush(tKeys["k_tx"]) into tPush
   -- ac = key confirmation over {ik:IK_A, ek:EK_A, ep:epoch} keyed by RK (5.3.4)
   put rtKeyConfirmMacFrom(tV["ik"], tV["ek"], tV["ep"], tKeys["rk"]) into tAc
   put rtBuildResp(pIdentityB, tPush["header"], tAc) into tRespF
   -- assemble the session B keeps
   put "handshaking" into tS["state"]
   put "responder" into tS["role"]
   put tV["ik"] into tS["peer_ik"]
   put tV["ep"] into tS["epoch"]
   put tKeys["rk"] into tS["rk"]
   put tKeys["k_tx"] into tS["k_tx"]
   put tKeys["k_rx"] into tS["k_rx"]
   put pIdentityB["ik_ed_pub"] into tS["my_ik"]
   put tPush["handle"] into tS["h_push"]
   put tV["ik"] into tS["peer_ik"]
   put tV["ek"] into tS["peer_ek"]        -- kept to recompute ac only
   put tRespF into tS["resp_frame"]
   put true into tS["ok"]
   return tS
end rtHandshakeAcceptInit

-- Step 9: B accepts A's header frame (the second 0x21) and inits its pull
-- stream; the session is now established.
function rtHandshakeAcceptHeader pSession, pHeaderBody
   local tD, tV, tS
   put pSession into tS
   put false into tS["ok"]
   put rtBdecode(pHeaderBody) into tD
   if not tD["ok"] then return tS
   put tD["value"] into tV
   if tV["t"] is not kTypeResp then return tS
   put sxSecretStreamInitPull(pSession["k_rx"], tV["hd"]) into tS["h_pull"]
   put "established" into tS["state"]
   put true into tS["ok"]
   return tS
end rtHandshakeAcceptHeader

-- =====================================================================
-- HANDSHAKE HELPERS: canonical bodies for signing / key confirmation
-- =====================================================================

-- Rebuild bencode(init dict without g) from a parsed init, for signature verify.
-- Deterministic because bencode sorts keys canonically (3.2), so signer and
-- verifier produce identical bytes.
private function rtInitSignBody pV
   local tF
   put rtBencInt(pV["v"]) into tF["v"]
   put rtBencInt(pV["t"]) into tF["t"]
   put rtBencBytes(pV["ik"]) into tF["ik"]
   put rtBencBytes(pV["ix"]) into tF["ix"]
   put rtBencBytes(pV["ek"]) into tF["ek"]
   put rtBencBytes(pV["sp"]) into tF["sp"]
   put rtBencBytes(pV["op"]) into tF["op"]
   put rtBencInt(pV["ep"]) into tF["ep"]
   return rtBencodeDict(tF)
end rtInitSignBody

-- Build the handshake-resp frame (5.3.3 step 6): { v, t, hd, ac, g }.
private function rtBuildResp pIdentityB, pHeaderB, pAc
   local tF, tSignBody, tSig, tBody
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencInt(kTypeResp) into tF["t"]
   put rtBencBytes(pHeaderB) into tF["hd"]
   put rtBencBytes(pAc) into tF["ac"]
   put rtBencodeDict(tF) into tSignBody   -- bencode(resp without g)
   put sxSignDetached(tSignBody, pIdentityB["ik_ed_sec"]) into tSig
   put rtBencBytes(tSig) into tF["g"]
   put rtBencodeDict(tF) into tBody
   return numToByte(kTypeResp) & tBody
end rtBuildResp

-- Rebuild bencode(resp without g) from a parsed resp, for signature verify.
private function rtRespSignBody pV
   local tF
   put rtBencInt(pV["v"]) into tF["v"]
   put rtBencInt(pV["t"]) into tF["t"]
   put rtBencBytes(pV["hd"]) into tF["hd"]
   put rtBencBytes(pV["ac"]) into tF["ac"]
   return rtBencodeDict(tF)
end rtRespSignBody

-- A header-only frame (5.3.3 step 8): { v, t, hd }, no signature (the stream it
-- opens is keyed by k_tx, which only the real A could derive).
private function rtHeaderFrame pHeader
   local tF
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencInt(kTypeResp) into tF["t"]
   put rtBencBytes(pHeader) into tF["hd"]
   return numToByte(kTypeResp) & rtBencodeDict(tF)
end rtHeaderFrame

-- The key-confirmation MAC (5.3.4): sxHashKeyed(bencode({ik, ek, ep}), RK, 32).
-- Two spellings: from a session record (initiator, step 7) and from raw fields
-- (responder builds it in step 6). Both bencode the SAME {ek, ik, ep} dict.
private function rtKeyConfirmMac pSession
   return rtKeyConfirmMacFrom(pSession["my_ik"], pSession["init_ek"], pSession["epoch"], pSession["rk"])
end rtKeyConfirmMac
private function rtKeyConfirmMacFrom pIkA, pEkA, pEpoch, pRk
   local tF
   put rtBencBytes(pIkA) into tF["ik"]
   put rtBencBytes(pEkA) into tF["ek"]
   put rtBencInt(pEpoch) into tF["ep"]
   return sxHashKeyed(rtBencodeDict(tF), pRk, kKeyLen)
end rtKeyConfirmMacFrom

-- =====================================================================
-- THE LIVE SESSION OVER rp1 (5.4)
-- =====================================================================

-- Send one application message: one secretstream chunk, padded to the 1024-byte
-- wire bucket, framed as subtype 0x22. tAd is empty (the stream binds order and
-- direction internally, 5.4.1). Returns the rp1 frame bytes to PW.send.
function rtSessionSend pSession, pPlain
   local tChunk
   put sxSecretStreamPush(pSession["h_push"], rtPadWire(pPlain), empty, false) into tChunk
   return numToByte(kTypeData) & tChunk
end rtSessionSend

-- Receive one 0x22 frame body (the bytes after the subtype). Returns ok/true|
-- false, plaintext (empty for a keepalive), and final (true if the sender closed
-- this direction, 5.5). A bad pull fails closed and the caller tears the
-- connection down (5.4.2, 3.10).
function rtSessionRecv pSession, pChunk
   local tPull, tR
   put false into tR["ok"]
   put sxSecretStreamPull(pSession["h_pull"], pChunk, empty) into tPull
   if the result is not empty then
      put "pull-failed (tamper/reorder/wrong-key)" into tR["error"]
      return tR
   end if
   put true into tR["ok"]
   if sxIsFinalTag(tPull["tag"]) then
      put true into tR["final"]      -- clean close of this direction (5.5)
   else
      put false into tR["final"]
      put rtUnpadWire(tPull["data"]) into tR["plaintext"]   -- 0 bytes for a keepalive
   end if
   return tR
end rtSessionRecv

-- A keepalive: an empty, padded, authenticated data chunk, indistinguishable on
-- the wire from a short data message (5.4.3), so it adds no fingerprint (matters
-- in cover-seed). Send every KEEPALIVE_SECONDS of send-idle.
function rtSessionKeepalive pSession
   return rtSessionSend(pSession, empty)
end rtSessionKeepalive

-- Close a direction cleanly: a FINAL secretstream chunk (5.5). A truncated
-- stream would fail to produce a FINAL tag, so truncation is detectable.
function rtSessionCloseFrame pSession, pFinalPlain
   local tChunk
   put sxSecretStreamPush(pSession["h_push"], rtPadWire(pFinalPlain), empty, true) into tChunk
   return numToByte(kTypeData) & tChunk
end rtSessionCloseFrame

-- Free both stream handles (idempotent, api-reference) on close/teardown.
command rtSessionFree pSession
   if pSession["h_push"] is not empty then sxFreeStream pSession["h_push"]
   if pSession["h_pull"] is not empty then sxFreeStream pSession["h_pull"]
   return empty
end rtSessionFree

-- =====================================================================
-- REKEY (5.6)
-- =====================================================================

-- Light rekey (5.6.1): advance the secretstream key in place, one 0x23 control
-- frame per direction, no new DH. Both sides must rekey at the same stream point
-- (the chunk after the 0x23 frame), or the next chunk fails to open.
function rtRekeyLightFrame
   local tF
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencInt(kTypeRekey) into tF["t"]
   put rtBencBytes("s") into tF["r"]     -- "s" = secretstream rekey
   return numToByte(kTypeRekey) & rtBencodeDict(tF)
end rtRekeyLightFrame

command rtRekeyLightApply pSession
   -- advance both directions at the deterministic rekey point (5.6.1)
   sxSecretStreamRekey pSession["h_push"]
   sxSecretStreamRekey pSession["h_pull"]
   return empty
end rtRekeyLightApply

-- Full rekey (5.6.2): a fresh ephemeral exchange giving a new RK and
-- post-compromise security. Builds the signed 0x23 "f" frame carrying a new
-- ephemeral public key; the peer answers symmetrically, then both mix
-- RK' = KDF(sxHash(RK || DHnew, 32)) and re-init the streams. This builder
-- produces one side's frame and the fresh ephemeral to keep.
function rtRekeyFullFrame pIdentity
   local tEk, tF, tSignBody, tSig, tR
   put sxBoxKeypair() into tEk
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencInt(kTypeRekey) into tF["t"]
   put rtBencBytes("f") into tF["r"]
   put rtBencBytes(tEk["public"]) into tF["ek"]
   put rtBencodeDict(tF) into tSignBody
   put sxSignDetached(tSignBody, pIdentity["ik_ed_sec"]) into tSig
   put rtBencBytes(tSig) into tF["g"]
   put (numToByte(kTypeRekey) & rtBencodeDict(tF)) into tR["frame"]
   put tEk["public"] into tR["ek_pub"]
   put tEk["secret"] into tR["ek_sec"]
   return tR
end rtRekeyFullFrame

-- Derive the post-rekey root and directional keys (5.6.2 step 3): mix the old RK
-- with the fresh DH over the two new ephemerals. pMyRole is "client"/"server"
-- for the DH pairing (the initiator of the rekey is the client).
function rtRekeyFullDerive pOldRk, pMyRole, pMyEkPub, pMyEkSec, pPeerEkPub, pMyIk, pPeerIk
   local tDhNew, tMix, tRkNew, tId0, tId1, tR
   put rtDhShared(pMyRole, pMyEkPub, pMyEkSec, pPeerEkPub) into tDhNew
   put sxHash(pOldRk & tDhNew, kKeyLen) into tMix     -- old RK mixed in (a ratchet step)
   put rtSessionRootKey(tMix) into tRkNew
   put rtSessionDirKey(tRkNew, true) into tId0
   put rtSessionDirKey(tRkNew, false) into tId1
   put tRkNew into tR["rk"]
   if rtKeyLess(pMyIk, pPeerIk) then
      put tId0 into tR["k_tx"]
      put tId1 into tR["k_rx"]
   else
      put tId1 into tR["k_tx"]
      put tId0 into tR["k_rx"]
   end if
   return tR
end rtRekeyFullDerive

-- =====================================================================
-- COVER-SEED RECOGNITION (5.7)
-- =====================================================================
-- Both peers genuinely seed a real lawful torrent and recognize each other in
-- the BEP10 extended handshake, with no magic bytes. The per-epoch token is
-- unlinkable across epochs (5.7.2) and placed where opaque client metadata sits.

-- Build the recognition token for this epoch (5.7.2): { i: tokenId, s: sig }.
-- tokenId folds in the recognition secret RS, the epoch, and the cover infohash
-- (foundation rtCoverRecognitionTokenId), so only a holder of RS can compute or
-- recognize it. pSignSec is the ed25519 secret to sign under: a per-epoch key in
-- recognition-key mode (default, more deniable) or the identity key in
-- identity-key mode (5.7.3).
function rtCoverBuildToken pRecogSecret, pEpoch, pCoverInfohash, pSignSec
   local tTokenId, tSig, tF
   put rtCoverRecognitionTokenId(pRecogSecret, pEpoch, pCoverInfohash) into tTokenId
   put sxSignDetached(tTokenId, pSignSec) into tSig
   put rtBencBytes(tTokenId) into tF["i"]
   put rtBencBytes(tSig) into tF["s"]
   return rtBencodeDict(tF)
end rtCoverBuildToken

-- Verify a candidate token from a peer's extended handshake (5.7.3 steps 3-4).
-- Recomputes the expected tokenId for the epoch window, constant-time compares
-- (sxMemEqual), then verifies the signature against the expected public key
-- (a per-epoch key or IK_pub). A tokenId match with a bad signature is treated
-- as an ordinary seeder and ignored (fail closed, 3.10). Returns ok/true|false.
function rtCoverVerifyToken pRecogSecret, pMyEpoch, pCoverInfohash, pTokenBencode, pExpectedSignPub
   local tD, tV, tOff, tEpoch, tExpectId, tMatched, tR
   put false into tR["ok"]
   put rtBdecode(pTokenBencode) into tD
   if not tD["ok"] then return tR
   put tD["value"] into tV
   put false into tMatched
   -- check epoch-1, epoch, epoch+1 for drift (5.7.3 step 3, 3.9)
   repeat for each item tOff in "-1,0,1"
      put (pMyEpoch + tOff) into tEpoch
      put rtCoverRecognitionTokenId(pRecogSecret, tEpoch, pCoverInfohash) into tExpectId
      if sxMemEqual(tV["i"], tExpectId) then
         put true into tMatched
         exit repeat
      end if
   end repeat
   if not tMatched then return tR      -- ordinary seeder, ignore (no error)
   -- verified tokenId: now the signature must hold (fail closed otherwise)
   if not sxSignVerifyDetached(tV["s"], tV["i"], pExpectedSignPub) then
      put "cover-token-bad-signature" into tR["error"]
      return tR
   end if
   put true into tR["ok"]
   put tEpoch into tR["epoch"]
   return tR
end rtCoverVerifyToken

-- =====================================================================
-- CONNECTION STATE MACHINE (5.8)
-- =====================================================================
-- idle -> handshaking -> established -> (rekeying) -> established, and any
-- auth/decrypt failure in any state -> closed (fail closed, 3.10). This helper
-- validates a transition and returns the new state, or "closed" on any failure
-- signal, so a half-authenticated session is never kept alive.
function rtSessionTransition pState, pEvent
   -- pEvent: "handshake-ok" | "rekey-start" | "rekey-ok" | "close" | "fail"
   if pEvent is "fail" or pEvent is "close" then return "closed"
   if pState is "idle" and pEvent is "handshake-start" then return "handshaking"
   if pState is "handshaking" and pEvent is "handshake-ok" then return "established"
   if pState is "established" and pEvent is "rekey-start" then return "rekeying"
   if pState is "rekeying" and pEvent is "rekey-ok" then return "established"
   -- any other combination is invalid; fail closed
   return "closed"
end rtSessionTransition
