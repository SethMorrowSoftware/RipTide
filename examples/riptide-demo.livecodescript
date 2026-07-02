script "riptide-demo"
-- =====================================================================
-- riptide-demo.livecodescript - the Phase 0 vertical-slice driver.
--
-- Wires the foundation + identity + rendezvous + session modules into the one
-- flow IMPLEMENTATION-PLAN.md calls Phase 0: identity + rendezvous + ONE
-- secretstream session over the BEP10 rp1 extension (the phantom swarm, doc 05
-- C2). Two instances derive the same rendezvous id from a shared pairwise
-- secret, find each other, run the X3DH handshake, and exchange one
-- authenticated encrypted message. This is the driver a two-pane demo stack (in
-- the spirit of sodium-demo) calls behind its buttons.
--
-- STATUS: this is the integration SHAPE, verified statically. It cannot run end
-- to end until TorrentXT exposes the upstream-blocked capabilities (11.2.1
-- arbitrary-id DHT announce, 11.2.3 rp1 extension messages, 11.2.5 connection
-- events, 11.2.6 phantom-swarm mode). Until then the crypto/derivation steps run
-- (and are pinned by tests/vectors/ + riptide-tests.livecodescript); the
-- announce/connect/send steps are the reconciliation points that light up when
-- the transport lands. Each such step is marked ON-ENGINE + UPSTREAM below.
-- =====================================================================

-- A demo pairwise secret PS. In a real deployment PS is a prior session root
-- (04 4.1 source 1), a kx agreement (source 2), or a passphrase (source 3). For
-- a local two-pane demo both panes can share one PS out of band.
function rtDemoPairwiseSecret pPassphrase
   -- source 3 (04 4.1): both panes type the same phrase; strong-phrase caveat
   -- applies (the public salt means the phrase carries all the entropy).
   return rtPairwiseFromPassphrase(pPassphrase)
end rtDemoPairwiseSecret

-- LISTENER side (the responder). Announce at the rendezvous ids for the epoch
-- window and wait for a peer. Returns the identity + PS + epoch context the
-- rest of the flow threads through.
command rtDemoListen pPassphrase
   local tId, tPs, tEpoch
   put rtNewIdentity() into tId
   put rtDemoPairwiseSecret(pPassphrase) into tPs
   put rtEpochNow(empty) into tEpoch
   -- ON-ENGINE + UPSTREAM (11.2.1/11.2.6): announce at rid across the window and
   -- accept an incoming rp1 connection on the bare swarm id.
   rtRendezvousAnnounce tPs, tEpoch
   -- ... the engine's connection event (11.2.5) then delivers the initiator's
   -- rendezvous-hello, which we verify with rtVerifyRendezvousHello before
   -- accepting the handshake-init with rtHandshakeAcceptInit.
   return "listening at rendezvous ids for epoch " & tEpoch
end rtDemoListen

-- INITIATOR side. Discover the listener at the rendezvous id, prove PS knowledge
-- with a rendezvous-hello, then run the handshake and send one message. This
-- sketches the call sequence; the transport calls are the reconciliation points.
command rtDemoConnectAndSend pPassphrase, pMessage, pPeerBundle, pPeerIkEd
   local tId, tPs, tEpoch, tPeers, tHello, tSession, tFrame
   put rtNewIdentity() into tId
   put rtDemoPairwiseSecret(pPassphrase) into tPs
   put rtEpochNow(empty) into tEpoch

   -- 1. discover the peer's IP:port at the rendezvous id (ON-ENGINE + UPSTREAM,
   --    11.2.1). Each returned candidate is unproven until the hello (4.3.1).
   put rtRendezvousDiscover(tPs, tEpoch) into tPeers
   if tPeers is empty then
      return "no peer found at rendezvous id this epoch; retry (4.4/N7)"
   end if

   -- 2. open an rp1 connection to the first candidate and send a rendezvous-hello
   --    proving PS knowledge (ON-ENGINE + UPSTREAM, 11.2.3). q = 0 for the
   --    initiator's hello.
   put rtBuildRendezvousHello(tPs, tEpoch, 0, empty) into tHello
   -- rtPwConnect line 1 of tPeers ; rtPwSend conn, tHello["frame"]  <- on-engine

   -- 3. on a mutually confirmed hello, run the X3DH handshake over rp1 using the
   --    peer's verified prekey bundle (fetched + verified per 02 2.4/2.5). This
   --    step is pure crypto and runs now; the frames move over rp1 on-engine.
   put rtHandshakeInit(tId, pPeerIkEd, pPeerBundle, empty, tEpoch) into tSession
   -- rtPwSend conn, tSession["frame"]                                <- on-engine
   -- ... receive the 0x21 resp, rtHandshakeFinishInit, send the header frame ...

   -- 4. once established, send one application message as a 0x22 secretstream
   --    frame (5.4.1). rtSessionSend runs now; PW.send moves it on-engine.
   if tSession["state"] is "established" then
      put rtSessionSend(tSession, pMessage) into tFrame
      -- rtPwSend conn, tFrame                                        <- on-engine
      return "message framed for send (" & the number of bytes of tFrame & " bytes)"
   end if
   return "handshake staged; awaiting rp1 transport to complete on-engine"
end rtDemoConnectAndSend
