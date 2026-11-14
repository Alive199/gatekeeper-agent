# Proof Gatekeeper Agent — zkVerify Agent Games

An autonomous agent for the **Proof Gatekeeper** track. The platform POSTs
signed transfer-request tasks; the agent verifies the HMAC, decides
APPROVE/REJECT with deterministic checks, generates a Groth16 proof locally
with snarkjs (gatekeeper circuit), submits it to Kurier, and returns a signed
response — all inside the 60-second deadline.

## How it works

- `POST /agent` — task endpoint (HMAC `x-agent-games-signature` over the raw
  body, verified before parsing). Handles the preflight handshake
  (`{ ok: true, protocolVersion: "v1" }`) and proof-gatekeeper tasks.
- `GET /` — health check.
- Decision checks: VK matches the registered key, balance ≥ minimum, not
  expired, recipient matches, amount ≤ max transfer, proof_tx not reused,
  deadline not passed. Anything else → REJECT (fail closed).
- Circuit inputs (reverse-engineered from `gatekeeper.wasm` + witness
  experiments): `minimum, publicBalance, amount, maxTransfer, recipient,
  conditionRecipient, expiryBlock, currentBlock, registeredVkHash,
  proofVkHash, decision, salt, taskId` — 13 inputs, 13 public signals
  `[hash, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
  taskId]`. `taskId` encoding defaults to `keccak256(task_id) mod p`
  (see `TASKID_ENCODING`; confirm against practice tasks).
- Proving is file-based (`wtns.calculate` → `groth16.prove`, ~0.4s) because
  `snarkjs.groth16.fullProve` hangs in this environment.

## Run

```bash
npm install
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET + KURIER_API_KEY
npm start              # listens on $PORT (default 3000)
npm test               # local harness: preflight + valid task + 5 traps + reuse
```

## Files

- `agent.mjs` — the service
- `kurier.mjs` — Kurier REST client (submit-proof, poll to Finalized)
- `gatekeeper.wasm`, `gatekeeper_final.zkey` — circuit artifacts from
  https://agentgames.zkverify.io/api/circuit-info
  (`vk_hash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`)
- `test.mjs` — local test harness

## Notes / open items

- `reason_code` values other than `VK_SUBSTITUTION` are best guesses
  (`INSUFFICIENT_BALANCE`, `EXPIRED`, `RECIPIENT_MISMATCH`,
  `AMOUNT_EXCEEDS_MAX`, `PROOF_REUSED`, `OK`) — confirm via practice tasks.
- `taskId` field encoding is a guess (keccak256 mod p) — confirm via
  practice tasks; switch with `TASKID_ENCODING`.
- Needs an always-on host: the 60s deadline + ~0.4s proving + Kurier polling
  rule out sleepy free tiers (Vercel Hobby 10s limit, Render needs a card).
