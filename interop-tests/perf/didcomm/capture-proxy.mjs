#!/usr/bin/env node
/**
 * Capture proxy — sits in front of the Traction agent's DIDComm inbound.
 * Forwards every request to the real agent AND appends the raw packed body
 * to a corpus file (ndjson: {ts, path, ctype, b64}). Point the agent's
 * ACAPY_ENDPOINT at this proxy so holders send through it; the captured
 * blobs are real, valid, encrypted DIDComm messages we can replay later.
 *
 *   PORT=9000 TARGET=http://localhost:8000 CORPUS=corpus.ndjson \
 *     node tests/perf/didcomm/capture-proxy.mjs
 *
 * Truncate CORPUS (or POST /__truncate) right before the basic-message send
 * loop so the corpus contains ONLY the messages you want to replay.
 */
import { createServer, request as httpRequest } from 'node:http'
import { createWriteStream, writeFileSync } from 'node:fs'
import { URL } from 'node:url'

const PORT = Number(process.env.PORT ?? 9000)
const TARGET = new URL(process.env.TARGET ?? 'http://localhost:8000')
const CORPUS = process.env.CORPUS ?? new URL('./corpus.ndjson', import.meta.url).pathname
// NO_FORWARD: capture-only — return 200 without hitting the agent. Removes the
// agent's DB-store latency from the capture loop (and keeps the agent's table
// clean during capture); the holder just needs a 200 to send the next message.
const NO_FORWARD = !!process.env.NO_FORWARD

let captured = 0
let out = createWriteStream(CORPUS, { flags: 'a' })

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks)))
  })
}

createServer(async (req, res) => {
  // control: truncate the corpus so only what follows is captured
  if (req.method === 'POST' && req.url === '/__truncate') {
    out.end(); writeFileSync(CORPUS, ''); out = createWriteStream(CORPUS, { flags: 'a' })
    captured = 0
    res.writeHead(200); return res.end('truncated\n')
  }
  const body = await readBody(req)
  // capture non-empty POST bodies (DIDComm messages) — async stream write so
  // the proxy event loop never blocks per message.
  if (req.method === 'POST' && body.length > 0) {
    out.write(JSON.stringify({
      ts: Date.now(),
      path: req.url,
      ctype: req.headers['content-type'] ?? '',
      b64: body.toString('base64'),
    }) + '\n')
    captured++
    if (captured % 500 === 0) console.log(`[capture] ${captured} messages`)
  }
  // capture-only: satisfy the holder without touching the agent
  if (NO_FORWARD && req.method === 'POST' && body.length > 0) {
    res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{}')
  }
  // forward to the real agent
  const fwd = httpRequest({
    hostname: TARGET.hostname, port: TARGET.port, path: req.url, method: req.method,
    headers: { ...req.headers, host: TARGET.host },
  }, (up) => {
    res.writeHead(up.statusCode ?? 502, up.headers)
    up.pipe(res)
  })
  fwd.on('error', (e) => { res.writeHead(502); res.end(String(e)) })
  fwd.end(body)
}).listen(PORT, () => {
  console.log(`[capture-proxy] :${PORT} → ${TARGET.origin}  corpus=${CORPUS}`)
})
