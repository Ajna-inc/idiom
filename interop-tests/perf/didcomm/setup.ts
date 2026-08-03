/**
 * One-shot setup for the DIDComm stress test: mint a tenant token, create an
 * OOB invitation on the operator (Traction tenant), have the holder
 * (wallet-agent) accept it, and wait for the connection to complete. Writes
 * { connId, token } to .conn.json for run.mjs to pick up.
 *
 * Run from tests/e2e (so the token helper's `docker compose exec` resolves):
 *   ACAPY_ADMIN_API_KEY=... COMPOSE_PROJECT_NAME=crms-e2e \
 *   npx ts-node --transpile-only ../perf/didcomm/setup.ts
 */
import { writeFileSync } from 'node:fs'
import path from 'node:path'

import { getTractionToken } from '../../e2e/fixtures/tractionToken'

const ACAPY = process.env.ACAPY_ADMIN_URL ?? 'http://localhost:8031'
const WALLET = process.env.WALLET_AGENT_URL ?? 'http://localhost:4501'
const TENANT = Number(process.env.E2E_TENANT_ID ?? 1)

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function main() {
  const { token } = await getTractionToken(undefined as never, TENANT)
  console.log('minted tenant token')

  // operator: create an OOB invitation (tenant-scoped, auto-accept)
  const invResp = await fetch(`${ACAPY}/out-of-band/create-invitation?auto_accept=true`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      handshake_protocols: ['https://didcomm.org/didexchange/1.1'],
      use_public_did: false,
    }),
  })
  const inv = (await invResp.json()) as { invitation_url?: string }
  if (!invResp.ok || !inv.invitation_url) {
    throw new Error(`create-invitation failed (${invResp.status}): ${JSON.stringify(inv)}`)
  }
  console.log('created OOB invitation')

  // holder: accept it
  const recvResp = await fetch(`${WALLET}/wallet/connections/receive-invitation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ invitation_url: inv.invitation_url }),
  })
  if (!recvResp.ok) throw new Error(`receive-invitation failed (${recvResp.status})`)
  console.log('holder received invitation; waiting for completion…')

  // wait for the holder connection to complete
  let connId = ''
  const deadline = Date.now() + 45_000
  while (Date.now() < deadline) {
    const listResp = await fetch(`${WALLET}/wallet/connections`)
    const list = (await listResp.json()) as unknown
    const conns = (Array.isArray(list) ? list : (list as { connections?: unknown[] }).connections) ?? []
    const done = (conns as Array<{ id?: string; connectionId?: string; state?: string }>).find(
      (c) => /complet|active|response/i.test(String(c.state)),
    )
    if (done) {
      connId = done.id ?? done.connectionId ?? ''
      break
    }
    await sleep(1000)
  }
  if (!connId) throw new Error('holder connection did not complete within 45s')

  const out = path.resolve(__dirname, '.conn.json')
  writeFileSync(out, JSON.stringify({ connId, token }, null, 2))
  console.log(`\nCONNECTED  connId=${connId}`)
  console.log(`wrote ${out}`)
}

main().catch((e) => {
  console.error('SETUP FAILED:', e)
  process.exit(1)
})
