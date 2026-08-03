#!/usr/bin/env node
/**
 * Minimal DIDComm "mock holder" sink — the §6 issuer-ceiling receiver.
 *
 * The seeded connections deliver to http://host.docker.internal:4502, so the
 * issuer (in docker) packs with the REAL connection keys and POSTs the JWE
 * here. This sink accepts every POST and returns 202 without unpacking —
 * isolating the issuer's pack+deliver ceiling from any holder work.
 *
 *   node tests/perf/didcomm/didcomm-sink.mjs   # listens on 0.0.0.0:4502
 */
import { createServer } from 'node:http'

const PORT = Number(process.env.SINK_PORT ?? 4502)
let received = 0
let lastLog = Date.now()

createServer((req, res) => {
  if (req.method === 'POST') {
    req.on('data', () => {})
    req.on('end', () => {
      received++
      if (received % 1000 === 0) {
        const now = Date.now()
        const rate = Math.round(1000 / ((now - lastLog) / 1000))
        lastLog = now
        console.log(`  received ${received}  (~${rate}/s)`)
      }
      res.writeHead(202)
      res.end()
    })
    return
  }
  if (req.url === '/count') {
    res.writeHead(200, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ received }))
  }
  res.writeHead(200)
  res.end('sink')
}).listen(PORT, () => console.log(`didcomm-sink listening on :${PORT} (POST -> 202)`))
