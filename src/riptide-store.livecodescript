script "riptide-store"
-- =====================================================================
-- riptide-store.livecodescript - the persistent, encrypted-at-rest state.
--
-- Unlike SodiumXT (stateless) and unlike a fire-and-forget call, Riptide holds
-- long-lived SECRET state (IMPLEMENTATION-PLAN.md section 4): the master seed,
-- per-contact records and verified key-transparency positions, unconsumed
-- one-time prekeys, and per-session ratchet chain keys and counters. This module
-- owns that store: its schema, its encryption at rest, and - the correctness-
-- critical part - the ordering rule that the advanced ratchet state is persisted
-- BEFORE a message is treated as delivered, so a crash skips a key (safe) rather
-- than reusing one (catastrophic).
--
-- ENCRYPTION AT REST (02 2.1, plan 4). The store blob is
--   salt(16) || sxSecretBox(arrayEncode(state), Kpw)
--   Kpw = sxPwHash(passphrase, salt, 32, "3", sxPwMemModerate())
-- The at-rest FORMAT is a client concern, not wire interop (02 2.1), so the state
-- array is serialized with the engine's arrayEncode/arrayDecode and then sealed;
-- only the passphrase KDF and the secretbox are cryptographic and both are
-- SodiumXT. The salt is stored beside the ciphertext (non-secret).
--
-- HONEST BOUNDARY (plan 4, CLAUDE.md rule 5). A secret in a LiveCode variable
-- cannot be mlock'ed or reliably wiped. This module minimizes how long keys sit
-- in script memory and keeps the passphrase-derived key transient; it does NOT
-- claim to protect against a compromised endpoint (threat-model N6).
--
-- STATUS: verified statically only; needs an on-engine pass.
-- =====================================================================

constant kSaltLen is 16       -- Argon2id salt (02 2.1)
constant kKeyLen is 32

-- ---- create / open / save ---------------------------------------------

-- Create a fresh, empty store protected by a passphrase. Returns an array with
-- "state" (the in-memory state) and "blob" (the encrypted-at-rest bytes to
-- write to disk). The state starts with the identity slot empty; the caller
-- seeds it with rtStoreSetIdentity.
function rtStoreCreate pPassphrase
   local tSalt, tState, tR
   put sxRandomBytes(kSaltLen) into tSalt
   put tSalt into tState["salt"]
   put 1 into tState["schema"]         -- store schema version
   put tState into tR["state"]
   put rtStoreSeal(tState, pPassphrase) into tR["blob"]
   return tR
end rtStoreCreate

-- Open an existing store blob with the passphrase. Returns ok/true|false and, on
-- success, "state". Fails closed if the passphrase is wrong (sxSecretBoxOpen
-- authenticates, so a wrong key or a tampered blob throws / returns failure,
-- 3.10) - surfaced, never guessed around.
function rtStoreOpen pBlob, pPassphrase
   local tSalt, tCipher, tKey, tPlain, tState, tR
   put false into tR["ok"]
   if the number of bytes of pBlob <= kSaltLen then return tR
   put byte 1 to kSaltLen of pBlob into tSalt
   put byte (kSaltLen + 1) to -1 of pBlob into tCipher
   put sxPwHash(pPassphrase, tSalt, kKeyLen, "3", sxPwMemModerate()) into tKey
   put sxSecretBoxOpen(tCipher, tKey) into tPlain
   if tPlain is empty then
      put "store-open-failed (wrong passphrase or tampered store)" into tR["error"]
      return tR
   end if
   put arrayDecode(tPlain) into tState
   put true into tR["ok"]
   put tState into tR["state"]
   return tR
end rtStoreOpen

-- Serialize + encrypt the state under the passphrase, reusing the salt already
-- in the state (so re-deriving Kpw is deterministic for this store).
private function rtStoreSeal pState, pPassphrase
   local tKey, tCipher
   put sxPwHash(pPassphrase, pState["salt"], kKeyLen, "3", sxPwMemModerate()) into tKey
   put sxSecretBox(arrayEncode(pState), tKey) into tCipher
   return pState["salt"] & tCipher
end rtStoreSeal

-- Persist the state to disk atomically: write to a temp path then rename, so a
-- crash mid-write cannot leave a half-written (unopenable) store. Reports via
-- the result. pPath is the store file path.
command rtStoreSave pState, pPassphrase, pPath
   local tBlob, tTmp
   put rtStoreSeal(pState, pPassphrase) into tBlob
   put pPath & ".tmp" into tTmp
   put tBlob into url ("binfile:" & tTmp)
   if the result is not empty then
      return "store-write-failed:" & the result
   end if
   -- atomic replace (rename is atomic within a filesystem)
   rename file tTmp to pPath
   return the result
end rtStoreSave

-- =====================================================================
-- SCHEMA ACCESSORS
-- =====================================================================
-- The state is a nested array. Top-level slots:
--   state["identity"]           the identity array (from riptide-identity)
--   state["contacts"][ikHex]    a contact record (verified IK, pinned log pos)
--   state["sessions"][sid]      per-session ratchet state (chain keys, counters)
--   state["opks"][id]           unconsumed one-time prekey secrets
--   state["feeds"] / ["groups"] channel state (docs 07/08)
-- Hex of the identity key is used as a stable ASCII map key.

function rtStoreSetIdentity pState, pIdentity
   put pIdentity into pState["identity"]
   return pState
end rtStoreSetIdentity

function rtStoreGetIdentity pState
   return pState["identity"]
end rtStoreGetIdentity

-- Contacts, keyed by the hex of their identity signing key.
function rtStorePutContact pState, pIkEdPub, pContactRecord
   put pContactRecord into pState["contacts"][sxBin2Hex(pIkEdPub)]
   return pState
end rtStorePutContact

function rtStoreGetContact pState, pIkEdPub
   return pState["contacts"][sxBin2Hex(pIkEdPub)]
end rtStoreGetContact

-- Pin a verified key-transparency position (02 2.6) for a contact.
function rtStorePinLog pState, pIkEdPub, pSeq, pHash
   local tHex
   put sxBin2Hex(pIkEdPub) into tHex
   put pSeq into pState["contacts"][tHex]["log_seq"]
   put pHash into pState["contacts"][tHex]["log_hash"]
   return pState
end rtStorePinLog

-- =====================================================================
-- THE RATCHET PERSISTENCE DISCIPLINE (plan 4, risk 4)
-- =====================================================================
-- The single most important correctness rule in the store. To send or receive a
-- ratcheted message you need this counter's message key, which is derived from
-- the current chain key. If you derived and USED the key, then advanced and only
-- THEN crashed before persisting, the next run would re-derive the SAME key for
-- the SAME counter and reuse it - a nonce/key reuse that breaks confidentiality.
-- So the order is fixed: advance and PERSIST the new chain key + counter FIRST,
-- return the message key SECOND. A crash after persist but before the message
-- goes out merely skips a counter (the peer tolerates a gap), which is safe.
--
-- pState is passed by the caller and MUST be saved (rtStoreSave) by this command
-- before the returned key is used. This command performs the derive + in-memory
-- advance + disk save as one step, then returns the message key via the result,
-- so a caller cannot accidentally use the key before the state is durable.
command rtStoreAdvanceRatchet pState, pSessionId, pPassphrase, pPath
   local tSess, tCounter, tChain, tStep
   put pState["sessions"][pSessionId] into tSess
   if tSess is empty then
      return "no-such-session"
   end if
   put tSess["send_counter"] into tCounter
   put tSess["send_chain"] into tChain
   -- derive next chain key + this message key (foundation rp-ratch step)
   put rtRatchetStep(tChain, tCounter) into tStep
   -- ADVANCE IN MEMORY: new chain key, bumped counter
   put tStep["next"] into pState["sessions"][pSessionId]["send_chain"]
   put (tCounter + 1) into pState["sessions"][pSessionId]["send_counter"]
   -- PERSIST BEFORE RETURNING THE KEY - the load-bearing ordering
   rtStoreSave pState, pPassphrase, pPath
   if the result is not empty then
      return "persist-failed:" & the result   -- do NOT hand out the key if not durable
   end if
   -- only now is it safe to use the message key; return it AND the counter used
   return tStep["mk"] & return & tCounter
end rtStoreAdvanceRatchet

-- Consume a one-time prekey atomically: delete its secret from the store and
-- persist that deletion BEFORE the handshake proceeds, so a replayed handshake
-- naming an already-consumed OPK is rejected (05 5.3.5, 02 2.7). Returns the
-- consumed secret via the result, or "opk-already-consumed".
command rtStoreConsumeOpk pState, pOpkId, pPassphrase, pPath
   local tSec
   put pState["opks"][pOpkId] into tSec
   if tSec is empty then
      return "opk-already-consumed"
   end if
   -- delete first, persist, THEN return the secret
   delete variable pState["opks"][pOpkId]
   rtStoreSave pState, pPassphrase, pPath
   if the result is not empty then
      return "persist-failed:" & the result
   end if
   return tSec
end rtStoreConsumeOpk
