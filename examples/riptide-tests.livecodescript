script "riptide-tests"
-- =====================================================================
-- riptide-tests.livecodescript - the on-engine self-test / interop harness.
--
-- This is the OpenXTalk-side counterpart to tests/vectors/ (the C oracle): it
-- drives the SAME deterministic derivations and canonical encodings through the
-- rt*/sx* handlers and asserts they match the frozen known answers from
-- 12-conformance-vectors.md and the C oracle's W.* wire vectors. Running it is
-- what turns "verified statically" into "verified on-engine" for the foundation,
-- and it is the reconciliation vehicle: if a sx* handler shape differs from the
-- assumptions in riptide.livecodescript, a KAT here fails loudly and points at
-- the exact call to fix (tests/vectors/README.md: drive the same derivations
-- through the sx* handlers so both paths pin to one truth).
--
-- It also runs the property / negative tests that a KAT cannot: an identity
-- round-trip, a prekey-bundle sign/verify, a two-instance handshake agreeing the
-- same session keys, and the security-relevant failures (tamper -> open fails,
-- replay -> dropped, wrong key -> fails). Those need two live instances for the
-- full interop path; the single-instance checks here exercise everything that
-- does not require the peer wire.
--
-- Run on-engine: put rtRunSelfTest() into field "report"  (or the message box).
-- Returns a text report; the last line is PASS or FAIL with a count.
-- =====================================================================

-- Fixed inputs (12.x). Hex; converted to bytes with sxHex2Bin at use.
constant kHexS is "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
constant kHexEdSeed is "cac73f09a0478224974a525036ebd73f9727ac8932162eb7fcfb2821ad7eecc7"
constant kHexIkPub is "672e8e0b259627f15c772ec0d61f15cd786ce2bc7244549255f9d6cfaac300b2"
constant kHexIkxPub is "5b9d094b6c0de5c16b3605cffd6d056144384855f82d02c352c5cffd3b60bf65"
constant kHexKxPub is "4a9789d887a6dcb2246f1a03833dab4c6c77c57633caef004190ba5f990a3d35"
constant kHexRid is "8d28959919bb0118762ea0c0b74d4ed7b216fc6f"
constant kHexPid is "e49c0e9369ac8e1a67de21abf2d9fe5f2304fdf2"
constant kHexInbox is "5b2db5b4b23a3f72ec7ab7bab4a730cc009e62d6"
constant kHexSn is "e4351a237b5150f780837f4ef69b4feb9496b48780cb07a8193803840e71a17c"
constant kHexBep44Sig is "86c843ec4cc2495e025e949dd72658ef01556dbbfb1f5d9b474b5957dbcb26a23497efe40f594387cc4f037075669efa4c42cb57c007eb0bddaa24934f3f740b"
constant kAdW1 is "d1:ei471000e1:qi0e1:ti4ee"
constant kSignBufW3 is "4:salt10:rp-prekeys3:seqi1e1:v2:hi"
constant kHexCardW4 is "64353a696b5f656433323a672e8e0b259627f15c772ec0d61f15cd786ce2bc7244549255f9d6cfaac300b2343a696b5f7833323a5b9d094b6c0de5c16b3605cffd6d056144384855f82d02c352c5cffd3b60bf65323a6b7833323a4a9789d887a6dcb2246f1a03833dab4c6c77c57633caef004190ba5f990a3d35313a7669316565"

-- module-level counters and report (script-locals)
local sPass, sFail, sReport

private command rtT_reset
   put 0 into sPass
   put 0 into sFail
   put empty into sReport
end rtT_reset

-- Assert a Data value equals an expected hex string (case-insensitive hex).
private command rtT_assertHex pLabel, pGotData, pExpectHex
   local tGot
   put sxBin2Hex(pGotData) into tGot
   if tGot is pExpectHex then
      add 1 to sPass
      put ("  ok   - " & pLabel) & return after sReport
   else
      add 1 to sFail
      put ("  FAIL - " & pLabel) & return after sReport
      put ("         got      " & tGot) & return after sReport
      put ("         expected " & pExpectHex) & return after sReport
   end if
end rtT_assertHex

-- Assert two byte/string values are identical (exact bytes).
private command rtT_assertBytes pLabel, pGot, pExpect
   if pGot is pExpect then
      add 1 to sPass
      put ("  ok   - " & pLabel) & return after sReport
   else
      add 1 to sFail
      put ("  FAIL - " & pLabel) & return after sReport
      put ("         got      " & pGot) & return after sReport
      put ("         expected " & pExpect) & return after sReport
   end if
end rtT_assertBytes

private command rtT_assertTrue pLabel, pCond
   if pCond then
      add 1 to sPass
      put ("  ok   - " & pLabel) & return after sReport
   else
      add 1 to sFail
      put ("  FAIL - " & pLabel) & return after sReport
   end if
end rtT_assertTrue

-- =====================================================================
-- THE SELF TEST
-- =====================================================================
function rtRunSelfTest
   local tS, tEdSeed, tId, tSs, tI
   local tIkxTest, tA, tB, tSignBuf, tSig, tAd, tCard
   rtT_reset

   -- registry invariants (no crypto needed)
   rtT_assertBytes "rtSelfCheck registry invariants", rtSelfCheck(), "ok"

   -- 12.1 identity derivation
   put sxHex2Bin(kHexS) into tS
   rtT_assertHex "12.1 edSeed (rtIdentitySeed id 0)", rtIdentitySeed(tS, 0), kHexEdSeed
   put rtIdentityFromSeed(tS) into tId
   rtT_assertHex "12.1 IK_pub", tId["ik_ed_pub"], kHexIkPub
   rtT_assertHex "12.1 IK_x_pub", tId["ik_x_pub"], kHexIkxPub
   rtT_assertHex "12.1 KX_pub", tId["kx_pub"], kHexKxPub

   -- 12.2 / 12.3 rendezvous + presence ids (ss = 0x42 x32, epoch 471000)
   put empty into tSs
   repeat with tI = 1 to 32
      put numToByte(66) after tSs        -- 0x42
   end repeat
   rtT_assertHex "12.2 rendezvous id", rtRendezvousId(tSs, 471000), kHexRid
   rtT_assertHex "12.3 presence id", rtPresenceId(tSs, 471000), kHexPid

   -- 12.4 inbox id (IK_x = 0x33 x32, counter 7)
   put empty into tIkxTest
   repeat with tI = 1 to 32
      put numToByte(51) after tIkxTest   -- 0x33
   end repeat
   rtT_assertHex "12.4 inbox id", rtInboxId(tIkxTest, 7), kHexInbox

   -- 12.5 safety number (a = 0xAA x32, b = 0xBB x32)
   put empty into tA
   put empty into tB
   repeat with tI = 1 to 32
      put numToByte(170) after tA        -- 0xAA
      put numToByte(187) after tB        -- 0xBB
   end repeat
   rtT_assertHex "12.5 safety number", rtSafetyNumber(tA, tB), kHexSn

   -- 12.6 BEP44 signature, built via rtBep44SignBuffer + signed with IK from S
   put rtBep44SignBuffer("rp-prekeys", 1, "2:hi") into tSignBuf
   rtT_assertBytes "W.3 BEP44 sign buffer bytes", tSignBuf, kSignBufW3
   put sxSignDetached(tSignBuf, tId["ik_ed_sec"]) into tSig
   rtT_assertHex "12.6 BEP44 signature", tSig, kHexBep44Sig
   rtT_assertTrue "12.6 BEP44 signature self-verifies", \
         sxSignVerifyDetached(tSig, tSignBuf, tId["ik_ed_pub"])

   -- W.1 AD binding + W.4 identity card (canonical bencode)
   put rtAdBinding(471000, 0, 4) into tAd
   rtT_assertBytes "W.1 AD binding bytes", tAd, kAdW1
   put rtIdentityCard(tId["ik_ed_pub"], tId["ik_x_pub"], tId["kx_pub"]) into tCard
   rtT_assertHex "W.4 identity card bencode", tCard, kHexCardW4

   -- property / round-trip checks
   rtT_identityRoundTrip tS
   rtT_bencodeRoundTrip
   rtT_prekeyBundleSignVerify tS
   rtT_negativeTamper

   -- summary
   put "-------------------" & return after sReport
   if sFail is 0 then
      put ("PASS (" & sPass & " checks)") after sReport
   else
      put ("FAIL (" & sFail & " of " & (sPass + sFail) & " checks failed)") after sReport
   end if
   return sReport
end rtRunSelfTest

-- Identity restore is deterministic: re-deriving from the same seed reproduces
-- every key (the one-backup-blob property, 02 2.1).
private command rtT_identityRoundTrip pS
   local tA, tB
   put rtIdentityFromSeed(pS) into tA
   put rtIdentityFromSeed(pS) into tB
   rtT_assertBytes "identity restore is deterministic", \
         tA["ik_ed_pub"] & tA["ik_x_pub"] & tA["kx_pub"], \
         tB["ik_ed_pub"] & tB["ik_x_pub"] & tB["kx_pub"]
end rtT_identityRoundTrip

-- bencode decode(encode(x)) == x for a representative record (the AD binding),
-- and a malformed input fails closed.
private command rtT_bencodeRoundTrip
   local tAd, tD
   put rtAdBinding(471000, 42, 16) into tAd
   put rtBdecode(tAd) into tD
   rtT_assertTrue "bencode decodes a dict", (tD["ok"] and tD["type"] is "dict")
   rtT_assertTrue "bencode round-trips e/q/t", \
         (tD["value"]["e"] is 471000 and tD["value"]["q"] is 42 and tD["value"]["t"] is 16)
   put rtBdecode("d1:ei5") into tD    -- truncated: no close
   rtT_assertTrue "bencode fails closed on truncation", (not tD["ok"])
end rtT_bencodeRoundTrip

-- A signed prekey verifies, and a tampered SPK does not (spk_sig proves SPK
-- belongs to IK, 02 2.4).
private command rtT_prekeyBundleSignVerify pS
   local tId, tSpk, tOk, tBadSpk
   put rtIdentityFromSeed(pS) into tId
   put rtNewSignedPrekey(tId) into tSpk
   put sxSignVerifyDetached(tSpk["spk_sig"], tSpk["spk_pub"], tId["ik_ed_pub"]) into tOk
   rtT_assertTrue "spk_sig verifies for the real SPK", tOk
   put tSpk["spk_pub"] into tBadSpk
   put numToByte((byteToNum(byte 1 of tBadSpk) + 1) mod 256) into byte 1 of tBadSpk
   rtT_assertTrue "spk_sig rejects a tampered SPK", \
         (not sxSignVerifyDetached(tSpk["spk_sig"], tBadSpk, tId["ik_ed_pub"]))
end rtT_prekeyBundleSignVerify

-- Negative: a flipped byte in a BEP44 value breaks the signature (tamper -> fail
-- closed, the security-relevant test).
private command rtT_negativeTamper
   local tS, tId, tSignBuf, tSig, tBad
   put sxHex2Bin(kHexS) into tS
   put rtIdentityFromSeed(tS) into tId
   put rtBep44SignBuffer("rp-prekeys", 1, "2:hi") into tSignBuf
   put sxSignDetached(tSignBuf, tId["ik_ed_sec"]) into tSig
   put rtBep44SignBuffer("rp-prekeys", 1, "2:HI") into tBad   -- one changed byte
   rtT_assertTrue "tampered BEP44 value fails signature verify", \
         (not sxSignVerifyDetached(tSig, tBad, tId["ik_ed_pub"]))
end rtT_negativeTamper
