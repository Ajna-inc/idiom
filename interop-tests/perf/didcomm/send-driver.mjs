#!/usr/bin/env node
/**
 * Issuer-send throughput driver — measures how fast the ACA-Py issuer can push
 * basic-messages to established connections, comparing the STOCK admin path vs
 * the didcomm_fastpath path. This is the outbound counterpart to replay.mjs
 * (which measures inbound). It's what exercises PR #462.
 *
 * Stock:    POST /connections/{id}/send-message
 * Fastpath: POST /didcomm-fastpath/connections/{id}/send-message
 * Both tenant-scoped (Bearer token), body {"content": "..."}.
 *
 *   TRACTION_TENANT_TOKEN=<jwt> CONNS_FILE=tests/perf/didcomm/conns.json \
 *   MODE=fastpath N=10000 W=20 node tests/perf/didcomm/send-driver.mjs
 *
 * Env:
 *   AGENT_ADMIN_URL   issuer admin base (default http://localhost:8031)
 *   TRACTION_TENANT_TOKEN  tenant JWT (required)
 *   CONN_IDS          comma list of connection ids, OR
 *   CONNS_FILE        conns.json ({conns:[...]} or [...])
 *   MODE              stock | fastpath   (default stock)
 *   N                 total messages (default 10000)
 *   W                 concurrent senders (default 20)
 */
import { readFileSync } from 'node:fs'

const BASE = process.env.AGENT_ADMIN_URL ?? 'http://localhost:8031'
const TOKEN = process.env.TRACTION_TENANT_TOKEN
const MODE = (process.env.MODE ?? 'stock').toLowerCase()
const N = Number(process.env.N ?? 10000)
const W = Number(process.env.W ?? 20)
if (!TOKEN) { console.error('TRACTION_TENANT_TOKEN required'); process.exit(1) }

let CONNS = (process.env.CONN_IDS ?? '').split(',').map((s) => s.trim()).filter(Boolean)
if (!CONNS.length && process.env.CONNS_FILE) {
  const j = JSON.parse(readFileSync(process.env.CONNS_FILE, 'utf8'))
  CONNS = Array.isArray(j) ? j : j.conns ?? j.connection_ids ?? []
}
if (!CONNS.length) { console.error('CONN_IDS or CONNS_FILE required'); process.exit(1) }

const path = (conn) =>
  MODE === 'fastpath'
    ? `${BASE}/didcomm-fastpath/connections/${conn}/send-message`
    : `${BASE}/connections/${conn}/send-message`

console.log(`send-driver: MODE=${MODE} N=${N} W=${W} conns=${CONNS.length} base=${BASE}`)

let sent = 0, errs = 0, i = 0
const t0 = Date.now()
async function worker() {
  while (true) {
    const n = i++
    if (n >= N) return
    const conn = CONNS[n % CONNS.length]
    try {
      const r = await fetch(path(conn), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` },
        body: JSON.stringify({ content: `perf-${n}` }),
      })
      if (r.ok) sent++; else errs++
      await r.arrayBuffer()
    } catch { errs++ }
    if ((n + 1) % 1000 === 0) {
      const rate = Math.round((n + 1) / ((Date.now() - t0) / 1000))
      console.log(`  ${n + 1}/${N}  ${rate}/s  (err ${errs})`)
    }
  }
}
await Promise.all(Array.from({ length: W }, worker))
const dt = (Date.now() - t0) / 1000
console.log(`\n-- ${MODE} --  sent ${sent} (err ${errs}) in ${dt.toFixed(1)}s  ->  ${Math.round(sent / dt)} msg/s`)
