/**
 * Credo 0.7 OID4VCI issuance benchmark (SD-JWT VC) on Postgres.
 *
 * Records → @credo-ts/drizzle-storage (Postgres via drizzle-orm).
 * KMS/keys → @credo-ts/askar with a Postgres store.
 * A single 0.7 agent issues + holds SD-JWT credentials over the full OID4VCI
 * HTTP path. Reported as creds/s — the Postgres counterpart of idiom(kanon) and
 * ACA-Py(askar-postgres).
 *
 * Prereq: migrations applied (see credo-oid4vci-bench.sh).
 *   N=200 npx tsx credo07-oid4vci-bench.ts
 */
// IMPORTANT: askar-nodejs must register the native binding into askar-shared
// BEFORE @credo-ts/askar evaluates (its KMS service captures the `askar` export
// at module-eval time). Keep this import first.
import { askar } from '@openwallet-foundation/askar-nodejs'
import { Agent, ClaimFormat, Kms, ConsoleLogger, LogLevel } from '@credo-ts/core'
import { AskarModule } from '@credo-ts/askar'
import { agentDependencies } from '@credo-ts/node'
import {
  OpenId4VcIssuerModule,
  OpenId4VcHolderModule,
  OpenId4VcIssuerApi,
  OpenId4VcHolderApi,
} from '@credo-ts/openid4vc'
import { DrizzleStorageModule } from '@credo-ts/drizzle-storage'
import { coreBundle } from '@credo-ts/drizzle-storage/core'
import { openid4vcBundle } from '@credo-ts/drizzle-storage/openid4vc'
import { drizzle } from 'drizzle-orm/node-postgres'
import { setGlobalConfig } from '@openid4vc/oauth2'
import express from 'express'
import { createRequire } from 'module'

// Localhost bench runs over http; allow non-https issuer URLs.
setGlobalConfig({ allowInsecureUrls: true })

const require = createRequire(import.meta.url)
const CREDO_VERSION = require('@credo-ts/core/package.json').version

const PG_HOST = 'localhost:5555'
const PG_URL = 'postgresql://postgres:pg@localhost:5555/credo_db'
const PORT = Number(process.env.PORT ?? 3070)
const N = Number(process.env.N ?? 200)
const CONCURRENCY = Number(process.env.CONCURRENCY ?? 1)
const CONFIG_ID = 'UniversityDegree'
const BASE = `http://localhost:${PORT}`

const app = express()
const database = drizzle(PG_URL)
let issuerDidUrl = ''

const agent = new Agent({
  config: { label: 'credo07-oid4vci-bench', allowInsecureHttpUrls: true, logger: new ConsoleLogger(LogLevel.off) },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({
      askar,
      // KMS/keys only — records go to drizzle/Postgres (avoids double StorageService).
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
              // The verified binding exposes each holder key as a ready jwk binding.
              holder: holderBinding.keys[0],
              payload: { vct: 'UniversityDegree', given_name: 'Alice', family_name: 'Holder', degree: 'BSc' },
              disclosureFrame: { _sd: ['given_name', 'family_name', 'degree'] },
            },
          ],
        }) as any,
    }),
    openId4VcHolder: new OpenId4VcHolderModule(),
  },
})

async function main() {
  await agent.initialize()
  const server = app.listen(PORT)
  console.log(`Credo ${CREDO_VERSION} OID4VCI issuer on ${BASE} (records=drizzle/pg, kms=askar/pg)`)

  // Issuer signing DID (did:key Ed25519).
  const created = await agent.dids.create({
    method: 'key',
    options: { createKey: { type: { kty: 'OKP', crv: 'Ed25519' } } },
  } as any)
  issuerDidUrl = created.didState.didDocument!.verificationMethod![0].id
  const issuerApi = agent.dependencyManager.resolve(OpenId4VcIssuerApi)
  const holderApi = agent.dependencyManager.resolve(OpenId4VcHolderApi)
  const issuerRecord = await issuerApi.createIssuer({
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

  // One reused holder key (mirrors idiom / ACA-Py single-holder-key benches).
  const holderKey = await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
  const holderPublicJwk = Kms.PublicJwk.fromPublicJwk(holderKey.publicJwk as any)
  const credentialBindingResolver = async () => ({ method: 'jwk' as const, keys: [holderPublicJwk] })

  const issueOne = async (): Promise<number> => {
    const { credentialOffer } = await issuerApi.createCredentialOffer({
      issuerId: issuerRecord.issuerId,
      credentialConfigurationIds: [CONFIG_ID],
      preAuthorizedCodeFlowConfig: {},
    })
    const resolved = await holderApi.resolveCredentialOffer(credentialOffer)
    const token = await holderApi.requestToken({ resolvedCredentialOffer: resolved })
    const { credentials } = await holderApi.requestCredentials({
      resolvedCredentialOffer: resolved,
      accessToken: token.accessToken,
      cNonce: token.cNonce,
      credentialBindingResolver,
    })
    const c: any = credentials?.[0]
    const compact =
      c?.record?.credentialInstances?.[0]?.compactSdJwtVc ??
      c?.credential?.compact ??
      (typeof c?.credential === 'string' ? c.credential : '')
    return typeof compact === 'string' && compact.length > 40 ? 1 : 0
  }

  await issueOne() // warm up (untimed)

  const t0 = Date.now()
  let ok = 0, i = 0
  let firstErr: unknown
  async function worker() {
    while (i < N) {
      i++
      try { ok += await issueOne() } catch (e) { if (!firstErr) firstErr = e }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker))
  const d = (Date.now() - t0) / 1000
  if (ok < N && firstErr) console.log('  first error:', (firstErr as Error).message)
  console.log(`  issued ${ok}/${N} SD-JWT credentials in ${d.toFixed(2)}s = ${(ok / d).toFixed(1)} creds/s (full OID4VCI HTTP path, Credo ${CREDO_VERSION}, records=drizzle/pg + kms=askar/pg)`)

  server.close()
  await agent.shutdown()
  process.exit(0)
}

main().catch((e) => { console.error(e); process.exit(1) })
