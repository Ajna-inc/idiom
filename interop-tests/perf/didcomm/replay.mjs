#!/usr/bin/env node
/**
 * Replay captured packed DIDComm messages at the Traction agent's inbound as
 * fast as possible — the replayer is a cheap HTTP loop (no crypto/wallet), so
 * ACA-Py itself becomes the bottleneck. This measures the raw DIDComm ceiling:
 * unpack + dispatch (+ store) throughput of the single ACA-Py event loop.
 *
 *   CORPUS=corpus.ndjson TARGET=http://localhost:8000 \
 *   STATS_CONTAINERS=crms-e2e-traction-agent-1 \
 *   LEVELS=8,16,32,64,128,256 TOTAL=5000 node tests/perf/didcomm/replay.mjs
 *
 * ACA-Py returns 200 on inbound *receipt* (queued), so accept-rate can outrun
 * processing — watch agent CPU (pins ~100%/core at the ceiling) and MEM
 * (climbing = the inbound queue is backing up, i.e. you're past the ceiling).
 */
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'

const cfg = {
  corpus: process.env.CORPUS ?? new URL('./corpus.ndjson', import.meta.url).pathname,
  target: (process.env.TARGET ?? 'http://localhost:8000').replace(/\/$/, ''),
  levels: (process.env.LEVELS ?? '8,16,32,64,128,256').split(',').map(Number),
  total: Number(process.env.TOTAL ?? 5000),
  statsContainers: (process.env.STATS_CONTAINERS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const pctl = (a, p) => (a.length ? a[Math.min(a.length - 1, Math.floor((p / 100) * a.length))] : 0)

// load corpus
const msgs = readFileSync(cfg.corpus, 'utf8').trim().split('\n').filter(Boolean).map((l) => {
  const { path, ctype, b64 } = JSON.parse(l)
  return { path: path || '/', ctype: ctype || 'application/didcomm-envelope-enc', body: Buffer.from(b64, 'base64') }
})
if (!msgs.length) { console.error(`empty corpus: ${cfg.corpus}`); process.exit(1) }

async function postOne(m) {
  const r = await fetch(cfg.target + m.path, { method: 'POST', headers: { 'Content-Type': m.ctype }, body: m.body })
  // drain body so sockets are reused
  await r.arrayBuffer()
  if (r.status >= 500) throw new Error(`status ${r.status}`)
}

function statsSampler(containers) {
  const peakCpu = {}, peakMem = {}
  let stop = false
  const loop = (async () => {
    while (!stop && containers.length) {
      const out = spawnSync('docker', ['stats', '--no-stream', '--format', '{{.Name}} {{.CPUPerc}} {{.MemPerc}}', ...containers], { encoding: 'utf8' })
      if (out.status === 0) for (const line of out.stdout.trim().split('\n')) {
        const [n, cpu, mem] = line.split(/\s+/)
        const c = parseFloat((cpu || '').replace('%', '')); const m = parseFloat((mem || '').replace('%', ''))
        if (n && !Number.isNaN(c)) peakCpu[n] = Math.max(peakCpu[n] ?? 0, c)
        if (n && !Number.isNaN(m)) peakMem[n] = Math.max(peakMem[n] ?? 0, m)
      }
      await sleep(1000)
    }
  })()
  return { peakCpu, peakMem, async stop() { stop = true; await loop } }
}

async function runLevel(C) {
  const stats = statsSampler(cfg.statsContainers)
  const lat = []; let errors = 0; let i = 0
  const t0 = performance.now()
  const worker = async () => {
    while (true) {
      const n = i++
      if (n >= cfg.total) return
      const m = msgs[n % msgs.length]
      const s = performance.now()
      try { await postOne(m); lat.push(performance.now() - s) } catch { errors++ }
    }
  }
  await Promise.all(Array.from({ length: C }, worker))
  const secs = (performance.now() - t0) / 1000
  await stats.stop()
  lat.sort((a, b) => a - b)
  return {
    C, throughput: Math.round(cfg.total / secs), errors,
    p50: Math.round(pctl(lat, 50)), p95: Math.round(pctl(lat, 95)), p99: Math.round(pctl(lat, 99)),
    cpu: { ...stats.peakCpu }, mem: { ...stats.peakMem },
  }
}

async function main() {
  console.log(`replay: ${msgs.length} captured msgs → ${cfg.target}  total/level=${cfg.total}`)
  console.log(`levels: ${cfg.levels.join(',')}  cpu: ${cfg.statsContainers.join(',') || '-'}\n`)
  const results = []
  for (const C of cfg.levels) {
    const r = await runLevel(C)
    const cpu = Object.entries(r.cpu).map(([n, v]) => `${n.replace('crms-e2e-', '')}:${Math.round(v)}%`).join(' ')
    const mem = Object.entries(r.mem).map(([n, v]) => `${n.replace('crms-e2e-', '')}:${Math.round(v)}%`).join(' ')
    console.log(`C=${String(C).padStart(4)}  ${String(r.throughput).padStart(6)} msg/s  p50/p95/p99=${r.p50}/${r.p95}/${r.p99}ms  err=${r.errors}  cpu[${cpu}] mem[${mem}]`)
    results.push(r)
    const peak = Math.max(...results.map((x) => x.throughput))
    if (r.throughput < peak * 0.85 && r.C > cfg.levels[0]) { console.log('  (throughput dropped past the knee — stopping)'); break }
  }
  const best = results.reduce((a, r) => (r.throughput > a.throughput ? r : a), { throughput: 0 })
  const hot = Object.entries(best.cpu).sort((a, b) => b[1] - a[1])[0]
  console.log(`\n── DIDComm ceiling ──`)
  console.log(`  peak throughput : ${best.throughput} msg/s  (at concurrency ${best.C})`)
  if (hot) console.log(`  agent CPU @ peak: ${hot[0].replace('crms-e2e-', '')} ${Math.round(hot[1])}%  → ~100%/core means ACA-Py's event loop is the limit`)
}

main().catch((e) => { console.error('FATAL', e); process.exit(1) })
