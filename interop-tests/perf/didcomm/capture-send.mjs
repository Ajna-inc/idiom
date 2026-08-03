#!/usr/bin/env node
/**
 * Drive the holder to send N distinct basic-messages over the proxy
 * connection, so the capture-proxy records N distinct packed DIDComm blobs.
 * Each message carries a unique content (seq + nonce) => unique @id + unique
 * ciphertext, so the replay corpus has no duplicate-message ambiguity.
 *
 *   WALLET_AGENT_URL=http://localhost:4501 CONN=<proxy-conn-id> \
 *   N=10000 W=8 node tests/perf/didcomm/capture-send.mjs
 */
import { readFileSync } from 'node:fs'
const WALLET = process.env.WALLET_AGENT_URL ?? 'http://localhost:4501'
const N = Number(process.env.N ?? 10000)
const W = Number(process.env.W ?? 8)
// One or more connection ids: CONN (single/comma-list), or CONNS_FILE (conns.json).
let CONNS = (process.env.CONN ?? '').split(',').map((s) => s.trim()).filter(Boolean)
if (!CONNS.length && process.env.CONNS_FILE) {
  CONNS = JSON.parse(readFileSync(process.env.CONNS_FILE, 'utf8')).conns
}
if (!CONNS.length) { console.error('CONN or CONNS_FILE required'); process.exit(1) }
console.log(`sending ${N} msgs across ${CONNS.length} connection(s), W=${W}`)

let sent = 0, errors = 0, i = 0
const t0 = Date.now()

async function worker() {
  while (true) {
    const n = i++
    if (n >= N) return
    try {
      const conn = CONNS[n % CONNS.length]
      const r = await fetch(`${WALLET}/wallet/connections/${conn}/basic-message`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: `cap-${n}-${Math.random().toString(36).slice(2)}` }),
      })
      if (!r.ok) errors++; else sent++
      await r.arrayBuffer()
    } catch { errors++ }
    if ((n + 1) % 500 === 0) {
      const rate = Math.round((n + 1) / ((Date.now() - t0) / 1000))
      console.log(`  sent ${n + 1}/${N}  (${rate}/s, err=${errors})`)
    }
  }
}

await Promise.all(Array.from({ length: W }, worker))
console.log(`done: sent=${sent} err=${errors} in ${Math.round((Date.now() - t0) / 1000)}s`)
