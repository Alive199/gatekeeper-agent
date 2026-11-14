// Kurier (zkVerify) REST client — mainnet, free API key.
// Docs: https://docs.zkverify.io/overview/getting-started/kurier
// Swagger: https://api.kurier.xyz/docs

const BASE = "https://api.kurier.xyz/api/v1";

async function postJson(url, body, timeoutMs = 15000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: ctrl.signal,
        });
        const text = await res.text();
        let json = null;
        try { json = JSON.parse(text); } catch { /* keep raw */ }
        if (!res.ok) throw new Error(`Kurier ${res.status}: ${text.slice(0, 300)}`);
        return json ?? text;
    } finally { clearTimeout(t); }
}

async function getJson(url, timeoutMs = 15000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const res = await fetch(url, { signal: ctrl.signal });
        const text = await res.text();
        if (!res.ok) throw new Error(`Kurier ${res.status}: ${text.slice(0, 300)}`);
        return JSON.parse(text);
    } finally { clearTimeout(t); }
}

/** Submit a Groth16 proof for verification. Returns { jobId, optimisticVerify, ... } */
export async function submitProof(apiKey, proof, publicSignals, vkHash) {
    return postJson(`${BASE}/submit-proof/${apiKey}`, {
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: vkHash },
    });
}

/** Poll a job until it reaches Finalized/Failed or the budget runs out. */
export async function waitFinalized(apiKey, jobId, budgetMs = 15000, pollMs = 5000) {
    const deadline = Date.now() + budgetMs;
    let last = null;
    while (Date.now() < deadline) {
        last = await getJson(`${BASE}/job-status/${apiKey}/${jobId}`);
        const status = last?.status;
        if (status === "Finalized" || status === "Failed") return last;
        await new Promise((r) => setTimeout(r, pollMs));
    }
    return last;
}

export async function jobStatus(apiKey, jobId) {
    return getJson(`${BASE}/job-status/${apiKey}/${jobId}`);
}
