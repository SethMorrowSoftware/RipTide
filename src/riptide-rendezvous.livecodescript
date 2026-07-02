script "riptide-rendezvous"
-- =====================================================================
-- riptide-rendezvous.livecodescript - rendezvous and presence (doc 04).
--
-- Where two parties meet on the DHT and how one learns another is online,
-- without a server and without a fixed, linkable address. This is signaling
-- only: it answers "at what 20-byte DHT id do we look for each other, and how do
-- we learn an IP:port there," then hands off to the session handshake (doc 05)
-- the moment the two have each other's address.
--
-- Composes the foundation (rid/pid/mid/coverId derivations, the AD binding, the
-- rendezvous-hello encoding) and SodiumXT. The DHT/peer-wire operations are
-- TorrentXT (bt*); their exact script handler names are confirmed on-engine and
-- funnelled through the rtDht*/rtPw* wrappers near the bottom, matching the
-- DHT.* / PW.* notation of 03 3.11 and 11-capabilities-required.md.
--
-- STATUS: verified statically only; needs an on-engine pass. The derivations
-- (rid 12.2, pid 12.3) are pinned; the rendezvous flow needs TorrentXT's
-- arbitrary-id DHT announce (11.2.1) and BEP10 rp1 (11.2.3), the upstream
-- blockers, before it runs end to end.
-- =====================================================================

constant kTypeRendezvousHello is 4   -- 0x04 (3.6, added by doc 04)
constant kProtoV is 1
constant kNonceLen is 16             -- 4.3.1 challenge nonce
constant kKeyLen is 32

-- =====================================================================
-- THE PAIRWISE SECRET PS (4.1)
-- =====================================================================
-- Every rendezvous/presence id is keyed by a 32-byte pairwise secret the two
-- parties already hold. Three sanctioned sources; this module builds sources 2
-- and 3 (source 1, a completed session's root key RK, is produced by doc 05 and
-- simply passed in as PS).

-- Source 2 (4.1): a pairwise secret from the identity kx keys, computable
-- offline once identity cards are exchanged and verified. Roles are fixed by the
-- identity keys: the party with the smaller IK_pub (raw byte compare) is the
-- crypto_kx client. Both parties then combine the SAME unordered pair of session
-- keys into PS.
--
-- CRYPTO NOTE (on-engine reconciliation point). crypto_kx derives two session
-- keys; libsodium guarantees client_rx == server_tx and client_tx == server_rx,
-- so both parties hold the identical unordered pair {firstHalf, secondHalf}. The
-- spec writes PS = sxHash(tRx & tTx, 32) in the client's orientation
-- (firstHalf & secondHalf). To reproduce that exact value the client hashes
-- (rx & tx) and the server hashes (tx & rx) - both equal sxHash(firstHalf &
-- secondHalf). This is verified by the on-engine self-test's "both sides agree"
-- property (12.7), not a KAT. The assumed SodiumXT calls return an array with
-- keys "rx" and "tx".
function rtPairwiseFromKx pIdentity, pContactKxPub, pContactIkEd
   local tSess, tFirst, tSecond
   if rtKeyLess(pIdentity["ik_ed_pub"], pContactIkEd) then
      -- I am the client
      put sxKeyExchangeClient(pIdentity["kx_pub"], pIdentity["kx_sec"], pContactKxPub) into tSess
      put tSess["rx"] into tFirst
      put tSess["tx"] into tSecond
   else
      -- I am the server: swap so (first,second) is the client's orientation
      put sxKeyExchangeServer(pIdentity["kx_pub"], pIdentity["kx_sec"], pContactKxPub) into tSess
      put tSess["tx"] into tFirst
      put tSess["rx"] into tSecond
   end if
   return sxHash(tFirst & tSecond, kKeyLen)   -- confine PS to the rendezvous purpose
end rtPairwiseFromKx

-- Source 3 (4.1): a pairwise secret from a shared passphrase, for parties who
-- can share a phrase out of band but have not exchanged keys. The salt is a
-- fixed, public, agreed domain string (both sides MUST use the identical salt),
-- so the passphrase carries all the entropy and MUST be strong. A bootstrap: the
-- first thing the parties do after meeting is exchange cards and run the doc-05
-- handshake, after which source 1 supersedes this.
function rtPairwiseFromPassphrase pPassphrase
   local tSalt
   -- tSalt = sxHash("rp-rndzv-pw/v1", 16); the foundation tag constant is used
   -- here via a literal so both implementations pin the identical public salt.
   put sxHash("rp-rndzv-pw/v1", 16) into tSalt
   return sxPwHash(pPassphrase, tSalt, kKeyLen, "3", sxPwMemModerate())
end rtPairwiseFromPassphrase

-- =====================================================================
-- THE ANNOUNCE / GETPEERS DISCOVERY DANCE (4.3), WITH EPOCH ADJACENCY (4.4)
-- =====================================================================

-- Announce yourself at the rendezvous ids for epoch-1, epoch, epoch+1, so you
-- are findable across a clock-drift boundary (4.4). A listener calls this and
-- refreshes on the DHT expiry cadence; keep the cadence modest (4.3) to avoid a
-- louder DHT footprint and UI cost on the single interpreter thread.
command rtRendezvousAnnounce pPairwiseSecret, pEpoch
   local tOff, tEpochN, tRid
   repeat for each item tOff in "-1,0,1"
      put (pEpoch + tOff) into tEpochN
      put rtRendezvousId(pPairwiseSecret, tEpochN) into tRid
      rtDhtAnnounce tRid
   end repeat
   return empty
end rtRendezvousAnnounce

-- Query the three adjacent rendezvous ids and return the union of candidate
-- IP:port peers (newline-separated). Each candidate is unproven (anyone can
-- announce at any id), so the caller gates each with a rendezvous-hello (4.3.1)
-- before spending handshake effort.
function rtRendezvousDiscover pPairwiseSecret, pEpoch
   local tOff, tEpochN, tRid, tPeers, tAll
   put empty into tAll
   repeat for each item tOff in "-1,0,1"
      put (pEpoch + tOff) into tEpochN
      put rtRendezvousId(pPairwiseSecret, tEpochN) into tRid
      put rtDhtGetPeers(tRid) into tPeers
      repeat for each line tPeer in tPeers
         if tPeer is not empty and tPeer is not among the lines of tAll then
            put tPeer & return after tAll
         end if
      end repeat
   end repeat
   -- delete a trailing return
   if the last char of tAll is return then delete the last char of tAll
   return tAll
end rtRendezvousDiscover

-- =====================================================================
-- THE RENDEZVOUS-HELLO CONTROL FRAME (4.3.1)
-- =====================================================================
-- Sent as the first rp1 control frame after a derived meeting (subtype 0x04). It
-- proves the sender derived rid from PS for this epoch, so the responder can
-- reject Sybil noise cheaply. The proof is an AEAD tag over empty plaintext,
-- keyed by the confirm key and bound to (epoch, q, type) as associated data, so
-- it cannot be replayed into another epoch (the confirm key rotates per epoch).

-- Build a rendezvous-hello. pQ is 0 for the initiator's hello, 1 for the
-- responder's echo (4.3.1). pEchoNonce, if given, is echoed in field n (the
-- responder echoes the initiator's nonce); otherwise a fresh 16-byte nonce is
-- drawn. Returns an array with "frame" (the 1-byte-subtype + bencode rp1 body)
-- and "nonce" (the nonce used, so the caller can match an echo).
function rtBuildRendezvousHello pPairwiseSecret, pEpoch, pQ, pEchoNonce
   local tNonce, tConfirm, tAd, tProof, tF, tBody, tR
   if pEchoNonce is empty then
      put sxRandomBytes(kNonceLen) into tNonce
   else
      put pEchoNonce into tNonce
   end if
   put rtRendezvousConfirmKey(pPairwiseSecret, pEpoch) into tConfirm
   put rtAdBinding(pEpoch, pQ, kTypeRendezvousHello) into tAd
   -- proof = AEAD tag (nonce+tag) over empty plaintext, bound to ad (4.3.1)
   put sxAeadEncrypt(empty, tAd, tConfirm) into tProof
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencInt(kTypeRendezvousHello) into tF["t"]
   put rtBencInt(pEpoch) into tF["e"]
   put rtBencBytes(tNonce) into tF["n"]
   put rtBencBytes(tProof) into tF["p"]
   put rtBencodeDict(tF) into tBody
   -- rp1 frame: 1-byte subtype then the bencode body (3.8)
   put numToByte(kTypeRendezvousHello) & tBody into tR["frame"]
   put tNonce into tR["nonce"]
   return tR
end rtBuildRendezvousHello

-- Verify a received rendezvous-hello against PS and the local epoch window.
-- Recomputes the confirm key and AD for the CLAIMED epoch, checks it is within
-- {myEpoch-1, myEpoch, myEpoch+1} (4.4), and decrypts the proof; success
-- authenticates the peer as a PS holder. Fails closed and surfaces the reason
-- on any mismatch (3.10) - the connection is then dropped by the caller. Returns
-- ok/true|false, and on success the peer's claimed epoch and echoed nonce.
function rtVerifyRendezvousHello pPairwiseSecret, pFrameBody, pQ, pMyEpoch
   local tR, tD, tV, tEpoch, tConfirm, tAd, tOpen
   put false into tR["ok"]
   put rtBdecode(pFrameBody) into tD
   if not tD["ok"] then return tR
   if tD["type"] is not "dict" then return tR
   put tD["value"] into tV
   if tV["v"] is not kProtoV then
      put "bad-version" into tR["error"]
      return tR
   end if
   if tV["t"] is not kTypeRendezvousHello then
      put "bad-type" into tR["error"]
      return tR
   end if
   put tV["e"] into tEpoch
   -- epoch adjacency: accept only epoch-1, epoch, epoch+1 (4.4)
   if abs(tEpoch - pMyEpoch) > 1 then
      put "epoch-out-of-window" into tR["error"]
      return tR
   end if
   put rtRendezvousConfirmKey(pPairwiseSecret, tEpoch) into tConfirm
   put rtAdBinding(tEpoch, pQ, kTypeRendezvousHello) into tAd
   put sxAeadDecrypt(tV["p"], tAd, tConfirm) into tOpen
   -- sxAeadDecrypt fails closed on a bad tag: a non-PS-holder cannot forge p.
   -- The plaintext is empty by construction; success is authentication.
   if the result is not empty then
      put "proof-failed (not a PS holder or wrong epoch)" into tR["error"]
      return tR
   end if
   put true into tR["ok"]
   put tEpoch into tR["epoch"]
   put tV["n"] into tR["nonce"]
   return tR
end rtVerifyRendezvousHello

-- =====================================================================
-- FIRST CONTACT BY PUBLIC KEY (4.5)
-- =====================================================================
-- When no PS exists, A reaches B at the meeting id derived from B's PUBLIC
-- identity key (rtFirstContactMeetingId, foundation). A sends a sealed intro so
-- A stays anonymous to onlookers and only B can open it (G7). B verifies A's
-- identity out of band / via the log (02 2.5) BEFORE trusting the keys, then runs
-- the doc-05 handshake.

-- Build the sealed first-contact intro (4.5). Returns the rp1 control frame
-- (subtype 0x04, the sealed intro as its body). The intro is the sender's
-- identity card sealed to B's box key.
function rtBuildFirstContactIntro pIdentity, pRecipientBoxPub
   local tIntro, tSealed
   -- intro = bencode({ v, t:4, ik_ed, ik_x, kx }) - A's card with the hello type
   put rtFirstContactIntroBody(pIdentity) into tIntro
   put sxSeal(rtPadRecord(tIntro), pRecipientBoxPub) into tSealed
   return numToByte(kTypeRendezvousHello) & tSealed
end rtBuildFirstContactIntro

private function rtFirstContactIntroBody pIdentity
   local tF
   put rtBencInt(kProtoV) into tF["v"]
   put rtBencInt(kTypeRendezvousHello) into tF["t"]
   put rtBencBytes(pIdentity["ik_ed_pub"]) into tF["ik_ed"]
   put rtBencBytes(pIdentity["ik_x_pub"]) into tF["ik_x"]
   put rtBencBytes(pIdentity["kx_pub"]) into tF["kx"]
   return rtBencodeDict(tF)
end rtFirstContactIntroBody

-- Open a sealed first-contact intro (B side). Returns ok/true|false plus the
-- sender's card fields on success. B MUST still verify these keys (safety number
-- / log) before treating the contact as trusted (4.5 step 4).
function rtOpenFirstContactIntro pSealed, pIdentity
   local tPadded, tBody, tD, tV, tR
   put false into tR["ok"]
   put sxSealOpen(pSealed, pIdentity["ik_x_pub"], pIdentity["ik_x_sec"]) into tPadded
   if the result is not empty then
      put "seal-open-failed" into tR["error"]
      return tR
   end if
   put rtUnpadRecord(tPadded) into tBody
   put rtBdecode(tBody) into tD
   if not tD["ok"] then return tR
   put tD["value"] into tV
   if tV["v"] is not kProtoV then return tR
   put true into tR["ok"]
   put tV["ik_ed"] into tR["ik_ed"]
   put tV["ik_x"] into tR["ik_x"]
   put tV["kx"] into tR["kx"]
   return tR
end rtOpenFirstContactIntro

-- =====================================================================
-- PRESENCE (4.6)
-- =====================================================================
-- "I am online and reachable," visible only to a specific contact. A presence id
-- under the rp-prsnc label (foundation), unlinkable to the meeting id. Announce
-- ONLY while online (the announce itself is the whole signal); stop announcing
-- the moment you go offline.
command rtPresenceAnnounce pPairwiseSecret, pEpoch
   local tOff, tPid
   repeat for each item tOff in "-1,0,1"
      put rtPresenceId(pPairwiseSecret, (pEpoch + tOff)) into tPid
      rtDhtAnnounce tPid
   end repeat
   return empty
end rtPresenceAnnounce

-- Watch a contact's presence: a non-empty result means "online now, at this
-- IP:port," which doubles as the rendezvous for the session it triggers (4.6).
function rtPresenceWatch pPairwiseSecret, pEpoch
   local tOff, tPid, tPeers, tAll
   put empty into tAll
   repeat for each item tOff in "-1,0,1"
      put rtPresenceId(pPairwiseSecret, (pEpoch + tOff)) into tPid
      put rtDhtGetPeers(tPid) into tPeers
      repeat for each line tPeer in tPeers
         if tPeer is not empty and tPeer is not among the lines of tAll then
            put tPeer & return after tAll
         end if
      end repeat
   end repeat
   if the last char of tAll is return then delete the last char of tAll
   return tAll
end rtPresenceWatch

-- =====================================================================
-- bt / peer-wire bridge (assumed TorrentXT script API; reconcile on-engine)
-- =====================================================================
-- The DHT.* / PW.* operations of 03 3.11 and doc 11. Names assumed; each is the
-- single reconciliation point for its operation. These are the upstream-blocked
-- capabilities (11.2.1 arbitrary-id announce, 11.2.3 rp1): Phase 0 cannot run
-- end to end until TorrentXT exposes them.
private command rtDhtAnnounce pId20
   btDhtAnnounce pId20            -- BEP5 announce_peer on an arbitrary 20-byte id (11.2.1)
end rtDhtAnnounce
private function rtDhtGetPeers pId20
   return btDhtGetPeers(pId20)    -- BEP5 get_peers -> newline list of ip:port (11.2.1)
end rtDhtGetPeers
