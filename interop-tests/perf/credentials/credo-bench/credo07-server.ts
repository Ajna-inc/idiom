/**
 * Credo 0.7 OID4VCI issuer SERVER (SD-JWT VC) on Postgres.
 *
 * Records → drizzle/Postgres, KMS → askar/Postgres. Exposes the standard
 * OID4VCI endpoints plus POST /bench/offer (mint a pre-authorized offer), so the
 * external multi-process HTTP holder (oid4vci-http-bench.py) drives issuance
 * over the wire — equivalent to idiom and ACA-Py. No in-process driving.
 *
 * Run with Node 22.18+ (native TS): see run-server.sh.
 */
import { askar } from '@openwallet-foundation/askar-nodejs'
import { Agent, ClaimFormat, ConsoleLogger, LogLevel } from '@credo-ts/core'
import { AskarModule } from '@credo-ts/askar'
import { agentDependencies } from '@credo-ts/node'
import { OpenId4VcIssuerModule, OpenId4VcIssuerApi } from '@credo-ts/openid4vc'
import { DrizzleStorageModule } from '@credo-ts/drizzle-storage'
import { coreBundle } from '@credo-ts/drizzle-storage/core'
import { openid4vcBundle } from '@credo-ts/drizzle-storage/openid4vc'
import { drizzle } from 'drizzle-orm/node-postgres'
import { setGlobalConfig } from '@openid4vc/oauth2'
import express from 'express'
import { createRequire } from 'module'

setGlobalConfig({ allowInsecureUrls: true })
const require = createRequire(import.meta.url)
const CREDO_VERSION = require('@credo-ts/core/package.json').version

const PG_HOST = 'localhost:5555'
const PG_URL = 'postgresql://postgres:pg@localhost:5555/credo_db'
const PORT = Number(process.env.PORT ?? 3070)
const CONFIG_ID = 'UniversityDegree'
const BASE = `http://localhost:${PORT}`

const app = express()
const database = drizzle(PG_URL)
let issuerDidUrl = ''
let issuerApiRef: any = null
let issuerIdRef = ''

// Register the control route BEFORE the agent mounts its OID4VCI router (which
// installs a 404 catch-all). Handler uses refs populated after initialize().
app.post('/bench/offer', express.json(), async (_req, res) => {
  try {
    const { credentialOffer } = await issuerApiRef.createCredentialOffer({
      issuerId: issuerIdRef,
      credentialConfigurationIds: [CONFIG_ID],
      preAuthorizedCodeFlowConfig: {},
    })
    const s = String(credentialOffer)
    // credentialOffer may be `...?credential_offer=<json>` (by value) or
    // `...?credential_offer_uri=<url>` (by reference); handle both.
    let offer
    if (s.includes('credential_offer=')) {
      offer = JSON.parse(decodeURIComponent(s.split('credential_offer=')[1]))
    } else if (s.includes('credential_offer_uri=')) {
      const uri = decodeURIComponent(s.split('credential_offer_uri=')[1])
      const r = await fetch(uri)
      offer = await r.json()
    } else {
      offer = JSON.parse(s)
    }
    res.json({ offer })
  } catch (e: any) {
    res.status(500).json({ error: e?.message })
  }
})

const agent = new Agent({
  config: { label: 'credo07-server', allowInsecureHttpUrls: true, logger: new ConsoleLogger(LogLevel.off) },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({
      askar,
      enableStorage: false,
      store: {
        id: 'credo07-bench',
        key: 'insecure-bench-key-0000000000',
        database: {
          type: 'postgres',
          config: { host: PG_HOST },
          credentials: { account: 'postgres', password: 'pg', adminAccount: 'postgres', adminPassword: 'pg' },
        },
      },
    }),
    drizzleStorage: new DrizzleStorageModule({ database, bundles: [coreBundle, openid4vcBundle] }),
    openId4VcIssuer: new OpenId4VcIssuerModule({
      baseUrl: BASE,
      app,
      credentialRequestToCredentialMapper: async ({ holderBinding }: any) =>
        ({
          credentialConfigurationId: CONFIG_ID,
          format: ClaimFormat.SdJwtDc,
          credentials: [
            {
              issuer: { method: 'did', didUrl: issuerDidUrl },
              holder: holderBinding.keys[0],
              payload: { vct: 'UniversityDegree', given_name: 'Alice', family_name: 'Holder', degree: 'BSc' },
              disclosureFrame: { _sd: ['given_name', 'family_name', 'degree'] },
            },
          ],
        }) as any,
    }),
  },
})

async function main() {
  await agent.initialize()
  const server = app.listen(PORT)
  const created = await agent.dids.create({
    method: 'key',
    options: { createKey: { type: { kty: 'OKP', crv: 'Ed25519' } } },
  } as any)
  issuerDidUrl = created.didState.didDocument!.verificationMethod![0].id
  issuerApiRef = agent.dependencyManager.resolve(OpenId4VcIssuerApi)
  const issuerRecord = await issuerApiRef.createIssuer({
    credentialConfigurationsSupported: {
      [CONFIG_ID]: {
        format: ClaimFormat.SdJwtDc,
        vct: 'UniversityDegree',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['EdDSA'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['EdDSA'] } },
      },
    },
  })
  issuerIdRef = issuerRecord.issuerId
  console.log(`Credo ${CREDO_VERSION} OID4VCI SERVER on ${BASE} (records=drizzle/pg, kms=askar/pg) — POST /bench/offer`)
  process.on('SIGINT', async () => { server.close(); await agent.shutdown(); process.exit(0) })
}

main().catch((e) => { console.error(e); process.exit(1) })
