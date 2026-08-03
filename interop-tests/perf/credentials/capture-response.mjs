#!/usr/bin/env node
/**
 * Response-capturing proxy. idiom uses inline return-route: the credential
 * REQUEST comes back as the HTTP *response* to the issuer's offer POST (not a
 * fresh inbound POST). So to capture requests we record RESPONSE bodies.
 *
 * Sits in front of the HOLDER's inbound: issuer POSTs the offer here, we forward
 * to the holder, and capture the holder's response body (the packed request) to
 * the corpus. Replaying those at the issuer drives real create_credential.
 *
 *   PORT=4600 TARGET=http://localhost:3031 CORPUS=requests.ndjson node capture-response.mjs
 */
import { createServer, request as httpRequest } from 'node:http'
import { createWriteStream } from 'node:fs'
import { URL } from 'node:url'

const PORT = Number(process.env.PORT ?? 4600)
const TARGET = new URL(process.env.TARGET ?? 'http://localhost:3031')
const CORPUS = process.env.CORPUS ?? new URL('./requests.ndjson', import.meta.url).pathname
const out = createWriteStream(CORPUS, { flags: 'a' })
let captured = 0

const readBody = (s) =>
  new Promise((r) => { const c = []; s.on('data', (d) => c.push(d)); s.on('end', () => r(Buffer.concat(c))) })

createServer(async (req, res) => {
  const body = await readBody(req)
  const fwd = httpRequest(
    { hostname: TARGET.hostname, port: TARGET.port, path: req.url, method: req.method, headers: { ...req.headers, host: TARGET.host } },
    async (up) => {
      const respBody = await readBody(up)
      // Capture non-empty response bodies — the inline return-route payloads
      // (the credential request answering the offer).
      if (respBody.length > 0) {
        out.write(JSON.stringify({ ts: Date.now(), path: '/', ctype: up.headers['content-type'] ?? 'application/didcomm-envelope-enc', b64: respBody.toString('base64') }) + '\n')
        captured++
        if (captured % 20 === 0) console.log(`[capture-resp] ${captured} responses`)
      }
      res.writeHead(up.statusCode ?? 502, up.headers)
      res.end(respBody)
    },
  )
  fwd.on('error', (e) => { res.writeHead(502); res.end(String(e)) })
  fwd.end(body)
}).listen(PORT, () => console.log(`[capture-response] :${PORT} → ${TARGET.origin}  corpus=${CORPUS}`))
