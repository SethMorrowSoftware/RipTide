script "riptide-transport"
-- =====================================================================
-- riptide-transport.livecodescript - the single TorrentXT (bt*) bridge.
--
-- Every call into TorrentXT is funnelled through this one module, exactly as the
-- sx* calls are funnelled through the foundation. The reason is the reason the
-- siblings give: an on-engine signature mismatch is then a ONE-PLACE fix, not a
-- scatter hunt. Nothing else in Riptide calls a bt* handler directly; rendezvous,
-- identity, and the demo call the rt* wrappers here.
--
-- Reconciled against TorrentXT ABI v10 (the Riptide-transport landing):
--   - DHT get_peers + announce on an arbitrary 20-byte id            (11.2.1)
--   - BEP44 put/get with the EXTERNAL signing hook (we sign, not it)  (11.2.2)
--   - the rp1 BEP10 custom peer-wire extension + poll events          (11.2.3)
--   - peer connect/handshake/message/disconnect events               (11.2.5)
--   - phantom-swarm join on a bare infohash, no metadata fetch        (11.2.6)
--
-- THE TWO SHAPES THAT DIFFER FROM THE FIRST-CUT ASSUMPTIONS, and why the code
-- above changed to match the shipped engine:
--
-- 1. Ids cross as 40-hex STRINGS, not raw 20-byte Data. rtRendezvousId and the
--    identity keys are raw bytes here, so every id/pubkey is sxBin2Hex'd at this
--    boundary (and only here).
--
-- 2. The DHT is ASYNCHRONOUS (the TorrentXT/OXT poll-drain world the CLAUDE.md
--    warns re-inherits from the sibling). btDhtGetPeers / btDhtGetMutable return
--    a status code IMMEDIATELY; the peers / the mutable item arrive LATER as a
--    dhtGetPeers / dhtMutableItem event drained by btPoll. So discovery is
--    "start a query" + "match the event when it lands", never a blocking return.
--    The rt*Start wrappers kick the query; the rt*Match helpers sift a drained
--    event list. The one interpreter thread is never blocked on the network.
--
-- 3. BEP44 signing stays in SodiumXT. btDhtBep44SignBuf builds the exact canonical
--    buffer TorrentXT will verify against; we sign THAT with sxSignDetached and
--    hand the detached signature to btDhtPutSigned, which verifies before storing.
--    The identity key never enters TorrentXT (11.2.2 option a). Signing the
--    engine's own buffer (rather than our rtBep44SignBuffer output) makes interop
--    robust even if the two builders ever diverged by a byte; the on-engine
--    self-test asserts they agree for the 12.6 inputs.
--
-- STATUS: verified statically; the bt* handler shapes are transcribed from the
-- TorrentXT ABI v10 api-reference and need the on-engine confirmation pass. The
-- poll-event representation (a List of Arrays, iterated with "for each element")
-- is the one remaining reconciliation point flagged inline.
-- =====================================================================

-- The default DHT port sentinel: 0 means "use the session's listen port"
-- (btDhtAnnounce contract). Declared literal, before first use (OXT rule).
constant kDhtListenPort is 0

-- The one TorrentXT session handle for this process. TorrentXT is explicitly a
-- single-session engine (btStartSession "creates THE one session"); a positive
-- handle is valid, 0 is invalid. Kept script-local and reached only through the
-- getter, so the handle threading that every bt* call needs lives in one place.
local sBtSession

-- =====================================================================
-- SESSION LIFECYCLE
-- =====================================================================

-- Start the one session (verifies the TorrentXT ABI first, engine-side) and
-- remember the handle. Reports the handle via the result; 0 means failure (and
-- the caller must not proceed - every other wrapper would no-op on a 0 handle).
command rtBtStart
   local tHandle
   put btStartSession() into tHandle
   put tHandle into sBtSession
   return tHandle
end rtBtStart

-- The current session handle (0 if not started). Every wrapper below reads it.
function rtBtSession
   if sBtSession is empty then return 0
   return sBtSession
end rtBtSession

-- Inject a session handle (for a demo/test that started the engine elsewhere, or
-- to reset). Keeps the field private to this module's discipline.
command rtBtSessionSet pHandle
   put pHandle into sBtSession
   return empty
end rtBtSessionSet

-- Tear the session down: pause, flush resume data, stop, join threads (idempotent
-- engine-side). Call on closeStack. After this the handle is stale, so clear it.
command rtBtStop
   if sBtSession is not empty and sBtSession is not 0 then
      btStopSession sBtSession
   end if
   put empty into sBtSession
   return empty
end rtBtStop

-- Drain ALL pending engine events in one FFI round-trip (the poll-drain beat).
-- Returns the List of event Arrays TorrentXT surfaces; the rt*Match helpers below
-- sift it. Keep the drain cadence modest (<= ~4 Hz, CLAUDE.md) off the UI beat.
function rtBtPoll
   return btPoll(rtBtSession())
end rtBtPoll

-- =====================================================================
-- ID ENCODING (the raw-bytes -> 40-hex boundary)
-- =====================================================================

-- A Riptide id is 20 raw bytes (sxHash(...,20)); TorrentXT wants a 40-hex string.
-- This is the ONLY place the conversion happens, so the rest of Riptide keeps
-- working in raw bytes (constant-time compares, KDF inputs) as the constitution
-- assumes.
function rtIdHex pId20
   return sxBin2Hex(pId20)
end rtIdHex

-- =====================================================================
-- DHT PRESENCE: announce / get_peers on an arbitrary id (11.2.1)
-- =====================================================================

-- Advertise that we serve peers for this id (BEP5 announce_peer on a bare id, no
-- real torrent behind it - that is exactly what makes a derived id a private
-- meeting point, doc 04). pPort empty -> the session listen port. Reports the
-- engine's status code via the result.
command rtDhtAnnounce pId20, pPort
   local tPort
   if pPort is empty then
      put kDhtListenPort into tPort
   else
      put pPort into tPort
   end if
   btDhtAnnounce rtBtSession(), rtIdHex(pId20), tPort
   return the result
end rtDhtAnnounce

-- Kick an asynchronous get_peers for this id. Returns the engine status code; the
-- actual peers arrive LATER as a dhtGetPeers event whose target is this id's hex,
-- collected by rtDhtMatchPeers from a drained poll list. Never blocks.
function rtDhtGetPeersStart pId20
   return btDhtGetPeers(rtBtSession(), rtIdHex(pId20))
end rtDhtGetPeersStart

-- Join a phantom swarm on a bare 20-byte id: libtorrent joins the swarm and
-- accepts peer-wire (+ BEP10) connections WITHOUT ever fetching an info dict
-- (11.2.6). This is what lets a listener accept rp1 connections at a rendezvous
-- id with no "torrent" behind it. pSavePath is required by the engine but nothing
-- is written for a metadata-less swarm. Returns the torrent handle (0 on failure).
function rtDhtJoinPhantom pId20, pSavePath
   return btAddInfohash(rtBtSession(), rtIdHex(pId20), pSavePath)
end rtDhtJoinPhantom

-- From a drained poll list, return the union of ip:port peers for every
-- dhtGetPeers event whose target is one of pTargetsHex (a return/newline list of
-- 40-hex ids we started queries for). De-duplicates. Each returned peer is still
-- UNPROVEN (anyone can announce at any id), so the caller gates it with a
-- rendezvous-hello before spending handshake effort (doc 04 4.3.1).
--
-- RECONCILIATION POINT: pEvents is TorrentXT's "List of Arrays"; we iterate it
-- with "for each element" and read the per-event Array keys (name/target/peers).
-- If the on-engine bridging surfaces the list differently, this loop is the
-- single place to adjust.
function rtDhtMatchPeers pEvents, pTargetsHex
   local tEv, tPeer, tAll
   put empty into tAll
   repeat for each element tEv in pEvents
      if tEv["name"] is "dhtGetPeers" and (tEv["target"] is among the lines of pTargetsHex) then
         repeat for each line tPeer in tEv["peers"]
            if tPeer is not empty and tPeer is not among the lines of tAll then
               put tPeer & return after tAll
            end if
         end repeat
      end if
   end repeat
   if the last char of tAll is return then delete the last char of tAll
   return tAll
end rtDhtMatchPeers

-- =====================================================================
-- BEP44 MUTABLE: the external signing hook (11.2.2)
-- =====================================================================

-- Build the EXACT canonical buffer BEP44 signs for a mutable item, engine-side
-- ([4:salt<salt>] 3:seqi<seq>e 1:v <value>). We sign this with SodiumXT so the
-- bytes we sign are byte-identical to the bytes TorrentXT re-derives and verifies
-- on put. pSeq is a decimal string (the no-64-bit-foreign-int FFI rule).
function rtDhtBep44SignBuf pSalt, pSeq, pValue
   return btDhtBep44SignBuf(pSalt, pSeq, pValue)
end rtDhtBep44SignBuf

-- Store a mutable item under an ed25519 public key with an EXTERNALLY produced
-- signature. TorrentXT verifies the signature against pPublicKey before storing
-- (returns -3 on a bad signature) and never holds the signing key. pPublicKey is
-- 64-hex, pSignature is 128-hex, pSeq is a decimal string. Reports the status
-- code via the result; the put is confirmed by a later dhtPut event.
command rtDhtPutSigned pPublicKeyHex, pSalt, pSeq, pValue, pSignatureHex
   btDhtPutSigned rtBtSession(), pPublicKeyHex, pSalt, pSeq, pValue, pSignatureHex
   return the result
end rtDhtPutSigned

-- Kick an asynchronous mutable get keyed by a 64-hex ed25519 public key (+ salt).
-- Returns the status code; the item arrives LATER as a dhtMutableItem event
-- (publicKey/value/seq/signature/salt/authoritative), matched by rtDhtMatchMutable.
function rtDhtGetMutableStart pPublicKeyHex, pSalt
   return btDhtGetMutable(rtBtSession(), pPublicKeyHex, pSalt)
end rtDhtGetMutableStart

-- From a drained poll list, return the dhtMutableItem event matching this public
-- key (+ salt), as an array ok/true|false plus value/seq/signature. Riptide STILL
-- verifies the signature itself upstream (never trust the transport, 3.10); this
-- only routes the event. signature is returned 128-hex (the caller sxHex2Bin's it
-- before sxSignVerifyDetached).
function rtDhtMatchMutable pEvents, pPublicKeyHex, pSalt
   local tEv, tR
   put false into tR["ok"]
   repeat for each element tEv in pEvents
      if tEv["name"] is "dhtMutableItem" and tEv["publicKey"] is pPublicKeyHex then
         -- salt may be absent on a salt-less item; match when both empty too
         if tEv["salt"] is pSalt then
            put true into tR["ok"]
            put tEv["value"] into tR["value"]
            put tEv["seq"] into tR["seq"]
            put tEv["signature"] into tR["signature"]
            put tEv["authoritative"] into tR["authoritative"]
            return tR
         end if
      end if
   end repeat
   return tR
end rtDhtMatchMutable

-- =====================================================================
-- BEP44 IMMUTABLE: sealed self-addressed values (11.2.2)
-- =====================================================================

-- Store an immutable value (1..1000 bytes); returns its target hash (40-hex, the
-- lookup key) or empty on failure. For a sealed envelope whose address the
-- recipient learns out of band (doc 03/09).
function rtDhtPutImmutable pData
   return btDhtPutImmutable(rtBtSession(), pData)
end rtDhtPutImmutable

-- Kick an asynchronous immutable get by 40-hex target. Value arrives as a
-- dhtImmutableItem event; matched by rtDhtMatchImmutable.
function rtDhtGetImmutableStart pTargetHex
   return btDhtGetImmutable(rtBtSession(), pTargetHex)
end rtDhtGetImmutableStart

-- From a drained poll list, return the dhtImmutableItem value for this target
-- (empty if not present yet).
function rtDhtMatchImmutable pEvents, pTargetHex
   local tEv
   repeat for each element tEv in pEvents
      if tEv["name"] is "dhtImmutableItem" and tEv["target"] is pTargetHex then
         return tEv["value"]
      end if
   end repeat
   return empty
end rtDhtMatchImmutable

-- =====================================================================
-- THE rp1 PEER-WIRE EXTENSION (11.2.3 / 11.2.5)
-- =====================================================================

-- Turn on the rp1 BEP10 extension for this session (installs the peer-wire
-- plugin; idempotent). A peer that also advertises rp1 is recognized as
-- Riptide-capable in the extended handshake. Call once after rtBtStart.
command rtPwEnable
   btRp1Enable rtBtSession()
   return the result
end rtPwEnable

-- Publish an opaque blob in our rp1 extended-handshake field (rp1_tok). This is
-- where the cover-seed recognition token goes (doc 05 5.7): a contact spots us on
-- a connection that is otherwise serving a real torrent, with no magic bytes. The
-- peer's own token is surfaced as "token" in its rp1Handshake event.
command rtPwSetToken pToken
   btRp1SetToken rtBtSession(), pToken
   return the result
end rtPwSetToken

-- Queue one rp1 message of opaque bytes to a peer. pPeer is the session-local
-- integer peer id from an rp1PeerConnected/rp1Handshake event. Fails (-3) if the
-- peer is unknown, gone, or has not completed the rp1 handshake. This is the
-- PW.send of doc 03 3.11: it moves a Riptide frame (subtype byte + body) as
-- opaque bytes; the framing is Riptide's, TorrentXT only moves bytes.
command rtPwSend pPeer, pData
   btRp1Send rtBtSession(), pPeer, pData
   return the result
end rtPwSend

-- Drain queued rp1 events (same List-of-Arrays shape as btPoll). Events:
--   rp1PeerConnected      { peer, infoHashV1, endpoint }
--   rp1Handshake          { peer, infoHashV1, btPeerId, endpoint, supportsRp1, token }
--   rp1Message            { peer, infoHashV1, payload }
--   rp1PeerDisconnected   { peer, infoHashV1 }
-- The caller routes each to the right session state machine (doc 05 5.8).
function rtPwPoll
   return btRp1Poll(rtBtSession())
end rtPwPoll

-- Convenience classifiers over a drained rp1 event list, so a caller does not
-- re-implement the "for each element" walk. Each returns the subset it names.

-- Every rp1Message payload from pPeer (in arrival order), one per line is unsafe
-- for binary, so return an array numbered 1..n carrying {peer, payload}.
function rtPwCollectMessages pEvents, pPeer
   local tEv, tOut, tN
   put 0 into tN
   repeat for each element tEv in pEvents
      if tEv["name"] is "rp1Message" and (pPeer is empty or tEv["peer"] is pPeer) then
         add 1 to tN
         put tEv["peer"] into tOut[tN]["peer"]
         put tEv["payload"] into tOut[tN]["payload"]
      end if
   end repeat
   return tOut
end rtPwCollectMessages

-- The first rp1Handshake event (with its recognition token and peer id), or an
-- array ok/false if none in this batch. Used to drive cover-seed recognition and
-- to learn the peer id to send to.
function rtPwFirstHandshake pEvents
   local tEv, tR
   put false into tR["ok"]
   repeat for each element tEv in pEvents
      if tEv["name"] is "rp1Handshake" then
         put true into tR["ok"]
         put tEv["peer"] into tR["peer"]
         put tEv["btPeerId"] into tR["btPeerId"]
         put tEv["endpoint"] into tR["endpoint"]
         put tEv["supportsRp1"] into tR["supportsRp1"]
         put tEv["token"] into tR["token"]
         return tR
      end if
   end repeat
   return tR
end rtPwFirstHandshake
