// Proof Gatekeeper agent — zkVerify Agent Games.
// POST /agent : verifies HMAC, decides APPROVE/REJECT deterministically,
// generates a local Groth16 proof (snarkjs, gatekeeper circuit),
// submits it to Kurier, and returns a signed response. 60s hard deadline.
// GET / : health check.
//
// Env: AGENT_GAMES_HMAC_SECRET (from dashboard Rotate Secret),
//      KURIER_API_KEY (free key from https://kurier.xyz),
//      PORT (default 3000), TASKID_ENCODING (keccak|sha256|fnv|numeric),
//      WASM_PATH / ZKEY_PATH (defaults: ./gatekeeper.wasm, ./gatekeeper_final.zkey)
import http from "http";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import * as snarkjs from "snarkjs";
import { keccak256 } from "js-sha3";
import { submitProof, waitFinalized } from "./kurier.mjs";

// NOTE: snarkjs groth16.fullProve hangs in this environment (its in-memory
// witness path stalls). Use the file-based path instead — wtns.calculate to
// a temp file, then groth16.prove from it. Proven fast (~2s end to end).
async function prove(inputs, taskId) {
    const tag = `${taskId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const inputPath = path.join(__dirname, `.prove-${tag}.json`);
    const wtnsPath = path.join(__dirname, `.prove-${tag}.wtns`);
    try {
        fs.writeFileSync(inputPath, JSON.stringify(inputs));
        await snarkjs.wtns.calculate(inputs, WASM_PATH, wtnsPath);
        const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_PATH, wtnsPath);
        return { proof, publicSignals: publicSignals.map(String) };
    } finally {
        for (const f of [inputPath, wtnsPath]) { try { fs.unlinkSync(f); } catch { /* ignore */ } }
    }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIELD_PRIME = BigInt("218882428718392752222464057732572773691635769694284537796234102026730753");
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const TASKID_ENCODING = process.env.TASKID_ENCODING || "keccak";
const WASM_PATH = process.env.WASM_PATH || path.join(__dirname, "gatekeeper.wasm");
const ZKEY_PATH = process.env.ZKEY_PATH || path.join(__dirname, "gatekeeper_final.zkey");
const SEEN_PATH = path.join(__dirname, "seen-proof-tx.json");
const RESPONSE_BUDGET_MS = 55000;

const log = (obj) => console.log(JSON.stringify({ t: new Date().toISOString(), ...obj }));

// ---- HMAC ----
function hmacHex(secret, body) {
    return crypto.createHmac("sha256", secret).update(body).digest("hex");
}
function verifyHmac(secret, rawBody, sig) {
    if (!secret || !sig) return false;
    const hex = hmacHex(secret, rawBody);
    const b64 = crypto.createHmac("sha256", secret).update(rawBody).digest("base64");
    const norm = sig.trim().replace(/^sha256=/, "");
    for (const cand of [hex, b64]) {
        try {
            if (crypto.timingSafeEqual(Buffer.from(norm), Buffer.from(cand))) return true;
        } catch { /* length mismatch */ }
    }
    return false;
}

// ---- field encodings ----
function toField(v) {
    if (typeof v === "string" && v.startsWith("0x")) return (BigInt(v) % FIELD_PRIME).toString();
    return (BigInt(v) % FIELD_PRIME).toString();
}
function fnv1a64(str) {
    let h = BigInt("0xCBF29CE484222325");
    for (let i = 0; i < str.length; i++) {
        h ^= BigInt(str.charCodeAt(i));
        h = (h * BigInt("0x100000001B3")) % (BigInt(2) ** BigInt(64));
    }
    return h;
}
function taskIdField(taskId) {
    const s = String(taskId ?? "");
    switch (TASKID_ENCODING) {
        case "sha256":
            return (BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex")) % FIELD_PRIME).toString();
        case "fnv":
            return (fnv1a64(s) % FIELD_PRIME).toString();
        case "numeric": {
            const m = s.match(/(\d+)\s*$/);
            return (m ? BigInt(m[1]) : BigInt(0)).toString();
        }
        case "keccak":
        default:
            return (BigInt("0x" + keccak256(s)) % FIELD_PRIME).toString();
    }
}

// ---- state: seen proof_tx + per-task salt ----
let seenProofTx = new Set();
try { seenProofTx = new Set(JSON.parse(fs.readFileSync(SEEN_PATH, "utf8"))); } catch { /* first run */ }
const saltByTask = new Map();
function saltFor(taskId) {
    if (!saltByTask.has(taskId)) {
        saltByTask.set(taskId, crypto.randomBytes(16).toString("hex"));
    }
    return (BigInt("0x" + saltByTask.get(taskId)) % FIELD_PRIME).toString();
}
function saveSeen() {
    try { fs.writeFileSync(SEEN_PATH, JSON.stringify([...seenProofTx])); } catch { /* ignore */ }
}

// ---- decision logic (deterministic, fail closed) ----
function decide(task) {
    const input = task.input || {};
    const REJ = (reason_code) => ({ decision: "REJECT", reason_code });
    try {
        const proofVk = toField(input.proof_vk ?? "0");
        const regVk = toField(input.registered_vk ?? "0");
        if (proofVk !== regVk) return REJ("VK_SUBSTITUTION");
        if (BigInt(input.public_balance ?? "0") < BigInt(input.minimum ?? "0")) return REJ("THRESHOLD_MISMATCH");
        if (BigInt(input.current_block ?? "0") > BigInt(input.expiry_block ?? "0")) return REJ("EXPIRED_CONDITION");
        if (String(input.recipient ?? "").toLowerCase() !== String(input.condition_recipient ?? "").toLowerCase()) return REJ("RECIPIENT_MISMATCH");
        if (BigInt(input.amount ?? "0") > BigInt(input.max_transfer ?? "0")) return REJ("AMOUNT_OVERFLOW");
        if (input.proof_tx && seenProofTx.has(String(input.proof_tx).toLowerCase())) return REJ("PROOF_REUSED");
        if (task.deadline_at) {
            const dl = Date.parse(task.deadline_at);
            if (!Number.isNaN(dl) && Date.now() > dl) return REJ("EXPIRED");
        }
    } catch (e) {
        return REJ("ERROR");
    }
    return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

function buildInputs(task, decision) {
    const input = task.input || {};
    return {
        minimum: BigInt(input.minimum ?? "0").toString(),
        publicBalance: BigInt(input.public_balance ?? "0").toString(),
        amount: BigInt(input.amount ?? "0").toString(),
        maxTransfer: BigInt(input.max_transfer ?? "0").toString(),
        recipient: BigInt(input.recipient ?? "0").toString(),
        conditionRecipient: BigInt(input.condition_recipient ?? "0").toString(),
        expiryBlock: BigInt(input.expiry_block ?? "0").toString(),
        currentBlock: BigInt(input.current_block ?? "0").toString(),
        registeredVkHash: toField(input.registered_vk ?? "0"),
        proofVkHash: toField(input.proof_vk ?? "0"),
        decision: decision === "APPROVE" ? "1" : "0",
        salt: saltFor(task.task_id),
        taskId: taskIdField(task.task_id),
    };
}

const responseCache = new Map(); // task_id -> { status, body, signature }

function sendSigned(res, obj) {
    const body = JSON.stringify(obj);
    const sig = HMAC_SECRET ? hmacHex(HMAC_SECRET, body) : "";
    res.writeHead(200, {
        "Content-Type": "application/json",
        ...(sig ? { "x-agent-games-signature": sig } : {}),
    });
    res.end(body);
}

async function handleTask(task, startedAt) {
    const taskId = task.task_id || "unknown";
    if (responseCache.has(taskId)) return responseCache.get(taskId);

    const { decision, reason_code } = decide(task);
    const input = task.input || {};
    if (input.proof_tx) {
        seenProofTx.add(String(input.proof_tx).toLowerCase());
        saveSeen();
    }

    let proof = null, publicSignals = null;
    const budgetLeft = () => RESPONSE_BUDGET_MS - (Date.now() - startedAt);
    try {
        if (budgetLeft() > 5000) {
            const t0 = Date.now();
            const r = await prove(buildInputs(task, decision), taskId);
            proof = r.proof;
            publicSignals = r.publicSignals;
            log({ task_id: taskId, step: "proved", ms: Date.now() - t0, decision });
        }
    } catch (e) {
        log({ task_id: taskId, step: "prove_failed", error: String(e).slice(0, 200), decision });
        proof = null; publicSignals = null;
    }

    // Kurier submission runs in the background: the platform's delivery
    // timeout (~15s) is shorter than waiting for on-chain finalization
    // (~12s+), so waiting would make every task look timed-out even
    // though the proof is fine. Respond as soon as the proof is ready;
    // the submission still lands on zkVerify and is logged here.
    if (proof && KURIER_API_KEY) {
        submitProof(KURIER_API_KEY, proof, publicSignals, VK_HASH).then(async (sub) => {
            const jobId = sub?.jobId;
            if (!jobId) return;
            try {
                const fin = await waitFinalized(KURIER_API_KEY, jobId, 30000);
                log({ task_id: taskId, step: "kurier", jobId, status: fin?.status, txHash: fin?.txHash || fin?.tx_hash || null });
            } catch (e) {
                log({ task_id: taskId, step: "kurier_failed", error: String(e).slice(0, 200) });
            }
        }).catch((e) => {
            log({ task_id: taskId, step: "kurier_failed", error: String(e).slice(0, 200) });
        });
    }

    const response = {
        decision,
        reason_code,
        ...(proof ? { proof, public_signals: publicSignals } : {}),
        ...(input.proof_tx ? { proof_tx: input.proof_tx } : {}),
    };
    const out = { status: 200, body: response };
    responseCache.set(taskId, out);
    return out;
}

const server = http.createServer((req, res) => {
    const startedAt = Date.now();
    if (req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", agent: "gatekeeper", hmac_configured: Boolean(HMAC_SECRET), kurier_configured: Boolean(KURIER_API_KEY) }));
        return;
    }
    if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

    const chunks = [];
    let tooBig = false;
    req.on("data", (c) => { chunks.push(c); if (Buffer.concat(chunks).length > 1_000_000) tooBig = true; });
    req.on("end", async () => {
        const raw = Buffer.concat(chunks);
        if (tooBig) { res.writeHead(413); res.end(); return; }
        // Fail closed without a secret: cannot verify inbound HMAC.
        if (!HMAC_SECRET) {
            log({ step: "no_hmac_secret", path: req.url });
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "agent not configured (no HMAC secret)" }));
            return;
        }
        const sig = req.headers["x-agent-games-signature"] || "";
        if (!verifyHmac(HMAC_SECRET, raw, sig)) {
            log({ step: "bad_hmac", path: req.url });
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "invalid signature" }));
            return;
        }
        let body;
        try { body = JSON.parse(raw.toString("utf8")); } catch {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "invalid JSON" }));
            return;
        }
        if (body?.type === "agent-games.preflight.v1") {
            log({ step: "preflight", agent_id: body.agent_id });
            return sendSigned(res, { ok: true, protocolVersion: "v1" });
        }
        if (body?.type !== "agent-games.proof-gatekeeper.v1") {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "unknown task type" }));
            return;
        }
        try {
            const out = await Promise.race([
                handleTask(body, startedAt),
                new Promise((resolve) => setTimeout(() => resolve({
                    status: 200,
                    body: {
                        decision: "REJECT", reason_code: "TIMEOUT",
                        ...(body.input?.proof_tx ? { proof_tx: body.input.proof_tx } : {}),
                    },
                }), RESPONSE_BUDGET_MS)),
            ]);
            log({ task_id: body.task_id, decision: out.body.decision, reason: out.body.reason_code, ms: Date.now() - startedAt });
            return sendSigned(res, out.body);
        } catch (e) {
            log({ task_id: body.task_id, step: "handler_error", error: String(e).slice(0, 200) });
            return sendSigned(res, {
                decision: "REJECT", reason_code: "ERROR",
                ...(body.input?.proof_tx ? { proof_tx: body.input.proof_tx } : {}),
            });
        }
    });
});

server.listen(PORT, () => {
    log({ step: "listening", port: PORT, wasm: WASM_PATH, zkey: ZKEY_PATH, taskid_encoding: TASKID_ENCODING });
});
