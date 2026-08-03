#!/usr/bin/env node
/**
 * DIDComm raw-message-rate stress test for the Traction / ACA-Py agent.
 *
 * Goal: find the ceiling of how many DIDComm messages the Traction agent can
 * PROCESS per second, on the local docker stack. Raw DIDComm is agent-to-agent
 * (holder <-> Traction) — it does NOT flow through crms-ui — so this measures
 * the single ACA-Py asyncio event loop (unpack/dispatch + Postgres write).
 *
 * Direction (default `inbound`): a Credo wallet-agent (holder) floods
 * `basicmessage` DIDComm messages at Traction. Traction unpacks + stores each
 * via the basicmessage_storage plugin. We use Traction's persisted
 * `GET /basicmessages` count as the "processed" sink — the honest signal,
 * because ACA-Py returns HTTP 200 on inbound *receipt* (queued), not on
 * processing. We ramp concurrency and watch for the knee: throughput plateaus
 * while send latency + processing backlog climb and the agent CPU pins ~100%
 * of one core.
 *
 * Zero dependencies — Node 18+ (global fetch). Run:
 *   node tests/perf/didcomm/run.mjs
 * See README.md for required env (CONN_IDS, TRACTION_TENANT_TOKEN).
 */

import { spawnSync } from 'node:child_process'

// ── config ───────────────────────────────────────────────────────────────
const cfg = {
  walletUrl: env('WALLET_AGENT_URL', 'http://localhost:4501'),
  acapyUrl: env('ACAPY_ADMIN_URL', 'http://localhost:8031'),
  token: env('TRACTION_TENANT_TOKEN', ''), // bearer for GET /basicmessages
  connIds: env('CONN_IDS', '').split(',').map((s) => s.trim()).filter(Boolean),
  levels: env('LEVELS', '1,2,4,8,16,32,64,128').split(',').map(Number),
  count: Number(env('COUNT', '2000')), // messages per level
  pollMs: Number(env('POLL_MS', '250')),
  drainTimeoutMs: Number(env('DRAIN_TIMEOUT_MS', '60000')),
  statsContainers: env('STATS_CONTAINERS', '').split(',').map((s) => s.trim()).filter(Boolean),
  mock: !!process.env.MOCK,
}

function env(k, d) {
  return process.env[k] ?? d
}

// ── tiny helpers ─────────────────────────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function pct(sorted, p) {
  if (sorted.length === 0) return 0
  const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[i]
}

async function jget(url, headers = {}) {
  const r = await fetch(url, { headers })
  if (!r.ok) throw new Error(`GET ${url} -> ${r.status} ${await r.text()}`)
  return r.json()
}

// ── sink: how many basic-messages has Traction PROCESSED (stored) ─────────
async function sinkCount() {
  const headers = cfg.token ? { Authorization: `Bearer ${cfg.token}` } : {}
  const data = await jget(`${cfg.acapyUrl}/basicmessages`, headers)
  // Real ACA-Py returns {results:[...]}. Mock returns {count:N} to stay cheap.
  if (typeof data.count === 'number') return data.count
  return Array.isArray(data.results) ? data.results.length : 0
}

// ── source: holder sends one basic-message over a connection ──────────────
async function sendOne(connId, body) {
  const r = await fetch(`${cfg.walletUrl}/wallet/connections/${connId}/basic-message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: JSON.stringify(body) }),
  })
  if (!r.ok) throw new Error(`send -> ${r.status}`)
}

async function discoverConnections() {
  if (cfg.connIds.length) return cfg.connIds
  const data = await jget(`${cfg.walletUrl}/wallet/connections`)
  const list = Array.isArray(data) ? data : (data.connections ?? [])
  const ids = list
    .filter((c) => !c.state || /complet|response|active/i.test(String(c.state)))
    .map((c) => c.id ?? c.connectionId ?? c.connection_id)
    .filter(Boolean)
  if (!ids.length) throw new Error('no usable holder connections; set CONN_IDS')
  return ids
}

// ── docker stats sampler (best-effort CPU attribution) ────────────────────
function makeStatsSampler(containers) {
  const peak = {}
  let stop = false
  const loop = (async () => {
    if (!containers.length) return
    while (!stop) {
      const out = spawnSync('docker', ['stats', '--no-stream', '--format', '{{.Name}} {{.CPUPerc}}', ...containers], { encoding: 'utf8' })
      if (out.status === 0) {
        for (const line of out.stdout.trim().split('\n')) {
          const [name, cpu] = line.split(/\s+/)
          const v = parseFloat((cpu || '').replace('%', ''))
          if (name && !Number.isNaN(v)) peak[name] = Math.max(peak[name] ?? 0, v)
        }
      }
      await sleep(1000)
    }
  })()
  return { peak, async stop() { stop = true; await loop } }
}

// ── one ramp level ────────────────────────────────────────────────────────
async function runLevel(C, conns) {
  const N = cfg.count
  const baseline = await sinkCount()
  const stats = makeStatsSampler(cfg.statsContainers)
  const sendLat = []
  let errors = 0
  let idx = 0

  const t0 = performance.now()
  const worker = async () => {
    while (true) {
      const seq = idx++
      if (seq >= N) return
      const conn = conns[seq % conns.length]
      const s = performance.now()
      try {
        await sendOne(conn, { seq, level: C, sentAt: Date.now() })
        sendLat.push(performance.now() - s)
      } catch {
        errors++
      }
    }
  }
  await Promise.all(Array.from({ length: C }, worker))
  const tSent = performance.now()
  const sentThroughput = N / ((tSent - t0) / 1000)
  const countAtSent = await sinkCount()
  const backlog = baseline + N - countAtSent // how far behind processing was

  // drain: wait until Traction has processed all N (or timeout)
  let count = countAtSent
  const drainStart = performance.now()
  let timedOut = false
  while (count < baseline + N) {
    if (performance.now() - drainStart > cfg.drainTimeoutMs) { timedOut = true; break }
    await sleep(cfg.pollMs)
    count = await sinkCount()
  }
  const tDrained = performance.now()
  await stats.stop()

  const drained = count - baseline
  const processedThroughput = drained / ((tDrained - t0) / 1000)
  sendLat.sort((a, b) => a - b)
  return {
    C, N, errors, backlog, timedOut,
    sentThroughput: Math.round(sentThroughput),
    processedThroughput: Math.round(processedThroughput),
    sendP50: Math.round(pct(sendLat, 50)),
    sendP95: Math.round(pct(sendLat, 95)),
    sendP99: Math.round(pct(sendLat, 99)),
    cpuPeak: { ...stats.peak },
  }
}

// ── report ────────────────────────────────────────────────────────────────
function printRow(r) {
  const cpu = Object.entries(r.cpuPeak).map(([n, v]) => `${n}:${Math.round(v)}%`).join(' ') || '-'
  console.log(
    `C=${String(r.C).padStart(4)}  ` +
    `sent/s=${String(r.sentThroughput).padStart(6)}  ` +
    `proc/s=${String(r.processedThroughput).padStart(6)}  ` +
    `backlog=${String(r.backlog).padStart(6)}  ` +
    `send p50/p95/p99=${r.sendP50}/${r.sendP95}/${r.sendP99}ms  ` +
    `err=${r.errors}  ` +
    `cpu[${cpu}]` +
    (r.timedOut ? '  DRAIN-TIMEOUT' : ''),
  )
}

function analyze(results, N) {
  // Saturation = the agent can't drain as fast as it's fed, so a backlog
  // builds. "Sustained" = levels where the agent kept up (backlog < 10% of N):
  // the real usable rate. "Ceiling" = max proc/s flat-out (even under backlog).
  const backlogThreshold = 0.1 * N
  const sustained = results.filter((r) => r.backlog < backlogThreshold)
  const maxSustained = sustained.reduce((a, r) => (r.processedThroughput > a.processedThroughput ? r : a), { processedThroughput: 0 })
  const ceiling = results.reduce((a, r) => (r.processedThroughput > a.processedThroughput ? r : a), { processedThroughput: 0 })
  const saturationOnset = results.find((r) => r.backlog >= backlogThreshold)
  return { maxSustained, ceiling, saturationOnset }
}

async function main() {
  console.log('DIDComm raw-message-rate stress test')
  console.log(`  wallet-agent : ${cfg.walletUrl}`)
  console.log(`  traction     : ${cfg.acapyUrl}`)
  console.log(`  levels       : ${cfg.levels.join(',')}   count/level=${cfg.count}`)
  const conns = await discoverConnections()
  console.log(`  connections  : ${conns.length} (${conns.slice(0, 3).join(', ')}${conns.length > 3 ? ', …' : ''})`)
  if (cfg.statsContainers.length) console.log(`  cpu sampling : ${cfg.statsContainers.join(', ')}`)
  console.log('')

  const results = []
  for (const C of cfg.levels) {
    const r = await runLevel(C, conns)
    results.push(r)
    printRow(r)
    // stop once we're clearly past the knee (throughput fell >20% from peak or drain timed out)
    const peak = Math.max(...results.map((x) => x.processedThroughput))
    if (r.timedOut || r.processedThroughput < peak * 0.8) {
      console.log('  (throughput degraded past knee — stopping ramp)')
      break
    }
  }

  const { maxSustained, ceiling, saturationOnset } = analyze(results, cfg.count)
  console.log('\n── result ─────────────────────────────────────────────')
  console.log(`  max SUSTAINED throughput  : ${maxSustained.processedThroughput} msg/s  (backlog stayed low, at concurrency ${maxSustained.C})`)
  console.log(`  saturated ceiling         : ${ceiling.processedThroughput} msg/s  (flat-out under backlog, at concurrency ${ceiling.C})`)
  if (saturationOnset) console.log(`  saturation onset          : concurrency ${saturationOnset.C} (backlog began to build)`)
  const hotCpu = Object.entries(ceiling.cpuPeak).sort((a, b) => b[1] - a[1])[0]
  if (hotCpu) console.log(`  hottest container @ peak  : ${hotCpu[0]} ${Math.round(hotCpu[1])}% CPU`)
  console.log('  → if the hottest is traction-agent near ~100%/core, that IS the DIDComm ceiling.')
  console.log('  → if it is the wallet-agent, the load generator is the limit: add more holders.')
}

main().catch((e) => { console.error('FATAL', e); process.exit(1) })
