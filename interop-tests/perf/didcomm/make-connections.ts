/**
 * Create N holder↔operator DIDComm connections (through the forward-mode
 * capture proxy) and write their holder-side connection ids to conns.json.
 * Used to test per-connection throughput scaling.
 *
 *   ACAPY_ADMIN_API_KEY=... COMPOSE_PROJECT_NAME=crms-e2e N=20 \
 *   npx ts-node --transpile-only ../perf/didcomm/make-connections.ts
 */
import { writeFileSync } from 'node:fs'
import path from 'node:path'

import { getTractionToken } from '../../e2e/fixtures/tractionToken'

const ACAPY = process.env.ACAPY_ADMIN_URL ?? 'http://localhost:8031'
const WALLET = process.env.WALLET_AGENT_URL ?? 'http://localhost:4501'
const TENANT = Number(process.env.E2E_TENANT_ID ?? 1)
const N = Number(process.env.N ?? 20)
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function completed(connId: string): Promise<boolean> {
  const list = (await (await fetch(`${WALLET}/wallet/connections`)).json()) as {
    connections?: { id: string; state: string }[]
  }
  const c = (list.connections ?? []).find((x) => x.id === connId)
  return !!c && /complet|active|response/i.test(c.state)
}

async function main() {
  const { token } = await getTractionToken(undefined as never, TENANT)
  const ids: string[] = []
  for (let i = 0; i < N; i++) {
    const inv = (await (
      await fetch(`${ACAPY}/out-of-band/create-invitation?auto_accept=true`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          handshake_protocols: ['https://didcomm.org/didexchange/1.1'],
          use_public_did: false,
        }),
      })
    ).json()) as { invitation_url?: string }
    if (!inv.invitation_url) throw new Error(`no invitation_url at ${i}`)

    const recv = (await (
      await fetch(`${WALLET}/wallet/connections/receive-invitation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invitation_url: inv.invitation_url, alias: `perf-${i}` }),
      })
    ).json()) as { connection_id?: string }
    const connId = recv.connection_id
    if (!connId) throw new Error(`no connection_id at ${i}`)

    const deadline = Date.now() + 30_000
    while (Date.now() < deadline && !(await completed(connId))) await sleep(500)
    if (!(await completed(connId))) throw new Error(`conn ${i} (${connId}) did not complete`)
    ids.push(connId)
    if ((i + 1) % 5 === 0) console.log(`  ${i + 1}/${N} connections up`)
  }
  const out = path.resolve(__dirname, 'conns.json')
  writeFileSync(out, JSON.stringify({ token, conns: ids }, null, 2))
  console.log(`\nMADE ${ids.length} connections → ${out}`)
}

main().catch((e) => { console.error('MAKE-CONNECTIONS FAILED:', e); process.exit(1) })
