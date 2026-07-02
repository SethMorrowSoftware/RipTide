script "riptide-demo"
-- =====================================================================
-- riptide-demo.livecodescript - the Phase 0 vertical-slice driver.
--
-- Wires foundation + identity + rendezvous + session + transport into the one
-- flow IMPLEMENTATION-PLAN.md calls Phase 0: identity + rendezvous + ONE
-- secretstream session over the BEP10 rp1 extension (the phantom swarm, doc 05
-- C2). Two instances derive the same rendezvous id from a shared pairwise
-- secret, join the phantom swarm there, get connected by libtorrent, prove PS
-- knowledge with a rendezvous-hello, run the X3DH handshake, and exchange one
-- authenticated encrypted message. This is the driver a two-pane demo stack (in
-- the spirit of sodium-demo) calls behind its buttons.
--
-- STATUS (updated): the TorrentXT capabilities this needs LANDED in ABI v10
-- (arbitrary-id DHT announce/get_peers 11.2.1, BEP10 rp1 11.2.3, connection
-- events 11.2.5, phantom-swarm mode 11.2.6), and the transport bridge
-- (riptide-transport.livecodescript) is reconciled to them. What remains is the
-- on-engine run: load the extensions on the OXT engine and drive two instances.
-- The crypto/derivation steps are pinned by tests/vectors/ + riptide-tests.
--
-- THE ASYNC SHAPE (why this is a poll loop, not a straight line). TorrentXT owns
-- network threads; the DHT lookup, the peer connection, and every rp1 message
-- are EVENTS. So the demo is a state machine driven by a poll beat, exactly as
-- CLAUDE.md's re-inherited TorrentXT discipline requires: never block the one
-- interpreter thread on the network. Call rtDemoPump on a modest timer (<= ~4 Hz)
-- to advance each side.
-- =====================================================================

-- Module-local demo state, one "side" per instance (a real app keys these by
-- session). Kept minimal: our identity, PS, epoch, role, the peer id once known,
-- the target hex list we are discovering, and the live rtSession record.
local sSide

-- A demo pairwise secret PS. In a real deployment PS is a prior session root
-- (04 4.1 source 1), a kx agreement (source 2), or a passphrase (source 3). For
-- a local two-pane demo both panes can share one PS out of band.
function rtDemoPairwiseSecret pPassphrase
   -- source 3 (04 4.1): both panes type the same phrase; strong-phrase caveat
   -- applies (the public salt means the phrase carries all the entropy).
   return rtPairwiseFromPassphrase(pPassphrase)
end rtDemoPairwiseSecret

-- Start the engine and turn on rp1 once. Both sides call this at launch. Reports
-- the session handle via the result (0 on failure - do not proceed).
command rtDemoStartEngine
   local tHandle
   put rtBtStart() into tHandle
   if tHandle is 0 then return 0
   rtPwEnable
   return tHandle
end rtDemoStartEngine

-- Join the rendezvous phantom swarm and set up this side. pRole is "initiator" or
-- "responder"; both JOIN the swarm at the current-epoch rid (that is what gets
-- them connected by libtorrent - the swarm membership is the channel, 11.2.6),
-- both announce across the epoch window (4.4), and the initiator additionally
-- starts a get_peers so it can observe candidates. The initiator/responder split
-- is a HANDSHAKE-layer role (who sends the 0x20 init), not a transport one.
command rtDemoJoin pPassphrase, pRole, pSavePath
   put empty into sSide
   put rtNewIdentity() into sSide["id"]
   put rtDemoPairwiseSecret(pPassphrase) into sSide["ps"]
   put rtEpochNow(empty) into sSide["epoch"]
   put pRole into sSide["role"]
   put empty into sSide["peer"]
   put empty into sSide["session"]
   put "waiting-peer" into sSide["phase"]
   -- both sides join the phantom swarm + announce so libtorrent connects them
   rtRendezvousListen sSide["ps"], sSide["epoch"], pSavePath
   if pRole is "initiator" then
      put rtRendezvousDiscoverStart(sSide["ps"], sSide["epoch"]) into sSide["targets"]
   end if
   return "joined rendezvous swarm for epoch " & sSide["epoch"] & " as " & pRole
end rtDemoJoin

-- The poll beat: drain the rp1 event queue once and advance this side's state
-- machine. Call on a timer. Returns a short human status line for the demo UI.
--
-- Flow (doc 04 4.3.1 -> doc 05 5.3):
--   rp1Handshake  -> we have a peer id; the initiator sends its rendezvous-hello
--                    (q=0) then its 0x20 handshake-init.
--   rp1Message    -> route by the 1-byte subtype: 0x04 hello (responder verifies,
--                    then expects init), 0x20 init (responder accepts), 0x21
--                    resp/header (initiator finishes; responder accepts header),
--                    0x22 data (established session receives one message).
command rtDemoPump pPeerBundle, pPeerIkEd, pMessage
   local tRpEvents, tHs, tMsgs, tN, tSubtype, tBody, tStatus
   if sSide is empty then return "not joined"
   put "idle" into tStatus
   -- 1. drain rp1 events (peer connect/handshake/messages) in one round trip
   put rtPwPoll() into tRpEvents
   -- 2. learn the peer id from the first rp1 handshake, if we do not have one
   if sSide["peer"] is empty then
      put rtPwFirstHandshake(tRpEvents) into tHs
      if tHs["ok"] then
         put tHs["peer"] into sSide["peer"]
         put "peer-connected" into sSide["phase"]
         -- the initiator opens: prove PS with a hello (q=0), then send the init
         if sSide["role"] is "initiator" then
            rtDemoSendHello 0
            rtDemoSendInit pPeerBundle, pPeerIkEd
            put "sent hello + init" into tStatus
         else
            put "peer connected; awaiting hello" into tStatus
         end if
      end if
   end if
   -- 3. route each rp1 message payload by its Riptide subtype byte (3.8)
   put rtPwCollectMessages(tRpEvents, sSide["peer"]) into tMsgs
   repeat with tN = 1 to the number of elements of tMsgs
      put byteToNum(byte 1 of tMsgs[tN]["payload"]) into tSubtype
      put byte 2 to -1 of tMsgs[tN]["payload"] into tBody
      put rtDemoRoute(tSubtype, tBody, pPeerBundle, pPeerIkEd, pMessage) into tStatus
   end repeat
   return tStatus
end rtDemoPump

-- Route one received frame by subtype. Returns a status line. Any auth/decrypt
-- failure fails closed (3.10): the session is dropped, never half-kept.
private command rtDemoRoute pSubtype, pBody, pPeerBundle, pPeerIkEd, pMessage
   local tHello, tAccept, tFinish, tRecv, tHeader
   -- 0x04 rendezvous-hello: the responder verifies PS knowledge for the window
   if pSubtype is 4 then
      put rtVerifyRendezvousHello(sSide["ps"], pBody, 0, sSide["epoch"]) into tHello
      if not tHello["ok"] then return "hello rejected: " & tHello["error"]
      put "hello-verified" into sSide["phase"]
      return "peer proved PS; awaiting init"
   end if
   -- 0x20 handshake-init: the responder accepts and replies with the 0x21 resp
   if pSubtype is 32 then
      put rtHandshakeAcceptInit(sSide["id"], pBody, sSide["epoch"], rtDemoMyPrekeys()) into tAccept
      if not tAccept["ok"] then return "init rejected: " & tAccept["error"]
      put tAccept into sSide["session"]
      rtPwSend sSide["peer"], tAccept["resp_frame"]
      return "accepted init; sent resp"
   end if
   -- 0x21 resp OR header: the initiator finishes (resp), the responder accepts
   -- the header. Distinguish by our role.
   if pSubtype is 33 then
      if sSide["role"] is "initiator" then
         put rtHandshakeFinishInit(sSide["session"], pBody) into tFinish
         if not tFinish["ok"] then return "resp rejected: " & tFinish["error"]
         put tFinish into sSide["session"]
         rtPwSend sSide["peer"], tFinish["header_frame"]   -- our own 0x21 header
         -- established: send the one application message (5.4.1)
         rtPwSend sSide["peer"], rtSessionSend(sSide["session"], pMessage)
         return "handshake complete; sent message"
      else
         put rtHandshakeAcceptHeader(sSide["session"], pBody) into tHeader
         if not tHeader["ok"] then return "header rejected"
         put tHeader into sSide["session"]
         return "session established; awaiting message"
      end if
   end if
   -- 0x22 data: an established session receives one application message
   if pSubtype is 34 then
      put rtSessionRecv(sSide["session"], pBody) into tRecv
      if not tRecv["ok"] then return "recv failed: " & tRecv["error"]
      if tRecv["final"] then return "peer closed the session"
      return "received message: " & tRecv["plaintext"]
   end if
   return "ignored subtype " & pSubtype
end rtDemoRoute

-- Send our rendezvous-hello to the peer (q=0 initiator, 1 responder echo).
private command rtDemoSendHello pQ
   local tHello
   put rtBuildRendezvousHello(sSide["ps"], sSide["epoch"], pQ, empty) into tHello
   rtPwSend sSide["peer"], tHello["frame"]
   return empty
end rtDemoSendHello

-- Send the 0x20 handshake-init using the peer's verified prekey bundle (fetched
-- and verified per 02 2.4/2.5). SPK-only here (empty OPK) to keep the demo short.
private command rtDemoSendInit pPeerBundle, pPeerIkEd
   put rtHandshakeInit(sSide["id"], pPeerIkEd, pPeerBundle, empty, sSide["epoch"]) into sSide["session"]
   rtPwSend sSide["peer"], sSide["session"]["frame"]
   return empty
end rtDemoSendInit

-- The responder's prekey material for accepting an init. In a real app these come
-- from the store (plan 4); the demo derives a fresh signed prekey so the shape is
-- exercised. Returns the array rtHandshakeAcceptInit expects.
private function rtDemoMyPrekeys
   local tSpk, tR
   put rtNewSignedPrekey(sSide["id"]) into tSpk
   put tSpk["spk_pub"] into tR["spk_pub"]
   put tSpk["spk_sec"] into tR["spk_sec"]
   return tR
end rtDemoMyPrekeys

-- Clean teardown: free the session streams and stop the engine (idempotent).
command rtDemoStop
   if sSide["session"] is not empty then rtSessionFree sSide["session"]
   rtBtStop
   put empty into sSide
   return empty
end rtDemoStop
