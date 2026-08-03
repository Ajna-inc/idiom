#!/usr/bin/env node
/**
 * Mock wallet-agent + Traction, ONLY for self-testing run.mjs (no real stack).
 *
 * Models a single-threaded agent with a bounded processing rate + backlog
 * queue, so the driver produces a realistic knee:
 *   - accepts sends fast (like ACA-Py returning 200 on receipt),
 *   - a background processor drains the queue at PROCESS_RATE msg/s,
 *   - GET /basicmessages reports the PROCESSED count.
 *
 * Run:  PROCESS_RATE=800 node tests/perf/didcomm/mock-stack.mjs
 * Then: MOCK=1 node tests/perf/didcomm/run.mjs   (defaults point at localhost)
 */
import { createServer } from 'node:http'

const PORT = Number(process.env.MOCK_PORT ?? 4501) // serves BOTH wallet + acapy paths
const PROCESS_RATE = Number(process.env.PROCESS_RATE ?? 800) // msg/s ceiling
const ACCEPT_LAT_MS = Number(process.env.ACCEPT_LAT_MS ?? 1) // per-send accept cost

let queued = 0
let processed = 0

// background processor: drain up to PROCESS_RATE/s, in 20ms ticks
const perTick = Math.max(1, Math.round(PROCESS_RATE / 50))
setInterval(() => {
  const take = Math.min(queued, perTick)
  queued -= take
  processed += take
}, 20)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

createServer(async (req, res) => {
  const url = req.url ?? ''
  // holder send: POST /wallet/connections/:id/basic-message
  if (req.method === 'POST' && /\/wallet\/connections\/.+\/basic-message$/.test(url)) {
    // read+discard body, simulate packing/accept cost, enqueue for processing
    await new Promise((r) => { req.on('data', () => {}); req.on('end', r) })
    if (ACCEPT_LAT_MS) await sleep(ACCEPT_LAT_MS)
    queued++
    res.writeHead(200, { 'content-type': 'application/json' })
    return res.end('{"ok":true}')
  }
  // discover connections
  if (req.method === 'GET' && url.startsWith('/wallet/connections')) {
    res.writeHead(200, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ connections: [
      { id: 'conn-a', state: 'completed' },
      { id: 'conn-b', state: 'completed' },
    ] }))
  }
  // sink: processed count (cheap — no giant array)
  if (req.method === 'GET' && url.startsWith('/basicmessages')) {
    res.writeHead(200, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ count: processed, results: [] }))
  }
  res.writeHead(404); res.end()
}).listen(PORT, () => {
  console.log(`[mock] wallet+traction on :${PORT}  PROCESS_RATE=${PROCESS_RATE}/s accept=${ACCEPT_LAT_MS}ms`)
})
