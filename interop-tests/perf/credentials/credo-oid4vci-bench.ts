/**
 * Credo OID4VCI issuance throughput benchmark (SD-JWT VC).
 *
 * A single Credo agent plays both issuer and holder: the OpenId4VcIssuerModule
 * hosts the real issuer endpoints (metadata/token/credential) on an Express
 * server, and the OpenId4VcHolderModule drives the full OID4VCI exchange
 * against them over HTTP (resolve → pre-auth token → credential request →
 * signed SD-JWT). Issuance is looped N times and reported as creds/s — the
 * apples-to-apples counterpart of idiom's oid4vci-issuance-bench.sh.
 *
 *   npx tsx credo-oid4vci-bench.ts            # N=200, port 3070
 *   N=500 PORT=3070 npx tsx credo-oid4vci-bench.ts
 */
import { Agent, KeyType, getJwkFromKey, ClaimFormat, ConsoleLogger, LogLevel } from '@credo-ts/core'
import { AskarModule } from '@credo-ts/askar'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)
const CREDO_VERSION = require('@credo-ts/core/package.json').version
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { agentDependencies } from '@credo-ts/node'
import {
  OpenId4VcIssuerModule,
  OpenId4VcHolderModule,
} from '@credo-ts/openid4vc'
import express from 'express'

const PORT = Number(process.env.PORT ?? 3070)
const N = Number(process.env.N ?? 200)
const CONFIG_ID = 'UniversityDegree-sdjwt'
const BASE_URL = `http://localhost:${PORT}/oid4vci`

const app = express()
const issuerRouter = express.Router()

const agent = new Agent({
  config: {
    label: 'credo-oid4vci-bench',
    walletConfig: { id: `credo-oid4vci-${Date.now()}`, key: 'bench-key-000000000000' },
    logger: new ConsoleLogger(LogLevel.off),
  },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({ ariesAskar }),
    openId4VcIssuer: new OpenId4VcIssuerModule({
      baseUrl: BASE_URL,
      router: issuerRouter,
      endpoints: {
        credential: {
          credentialRequestToCredentialMapper: async ({ holderBinding }) => ({
            credentialSupportedId: CONFIG_ID,
            format: ClaimFormat.SdJwtVc,
            issuer: { method: 'did', didUrl: issuerDidUrl },
            holder: holderBinding,
            payload: {
              vct: 'UniversityDegree',
              given_name: 'Alice',
              family_name: 'Holder',
              degree: 'BSc',
            },
            disclosureFrame: { given_name: true, family_name: true, degree: true } as any,
          }),
        },
      },
    }),
    openId4VcHolder: new OpenId4VcHolderModule(),
  },
})

let issuerDidUrl = ''

async function main() {
  await agent.initialize()
  app.use('/oid4vci', issuerRouter)
  const server = app.listen(PORT)
  console.log(`Credo OID4VCI issuer listening on ${BASE_URL}`)

  // Issuer signing DID (did:key Ed25519).
  const created = await agent.dids.create({ method: 'key', options: { keyType: KeyType.Ed25519 } })
  const issuerDid = created.didState.did!
  issuerDidUrl = created.didState.didDocument!.verificationMethod![0].id
  console.log(`Issuer DID: ${issuerDid}`)

  // Register the SD-JWT credential configuration.
  const issuerRecord = await agent.modules.openId4VcIssuer.createIssuer({
    credentialConfigurationsSupported: {
      [CONFIG_ID]: {
        format: ClaimFormat.SdJwtVc as any,
        vct: 'UniversityDegree',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['EdDSA'],
      },
    } as any,
  })

  // One reused holder key (mirrors idiom's single-holder-key bench).
  const holderKey = await agent.wallet.createKey({ keyType: KeyType.Ed25519 })
  const holderBindingResolver = async () => ({ method: 'jwk' as const, jwk: getJwkFromKey(holderKey) })

  const issueOne = async (): Promise<number> => {
    const { credentialOffer } = await agent.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: issuerRecord.issuerId,
      offeredCredentials: [CONFIG_ID],
      preAuthorizedCodeFlowConfig: { userPinRequired: false },
    })
    const resolved = await agent.modules.openId4VcHolder.resolveCredentialOffer(credentialOffer)
    const creds = await agent.modules.openId4VcHolder.acceptCredentialOfferUsingPreAuthorizedCode(
      resolved,
      { credentialBindingResolver: holderBindingResolver },
    )
    const c: any = creds[0]
    const compact = c?.compact ?? c?.credential?.compact ?? ''
    return typeof compact === 'string' && compact.length > 40 ? 1 : 0
  }

  // Warm up (JIT + first-call setup), untimed.
  await issueOne()

  // Timed batch. A single Credo agent is one JS event loop serving both roles,
  // so parallel requests only race on shared session state without adding
  // throughput — sequential issuance is the honest ceiling. Override with
  // CONCURRENCY to experiment.
  const CONCURRENCY = Number(process.env.CONCURRENCY ?? 1)
  const t0 = Date.now()
  let ok = 0
  let i = 0
  let firstErr: unknown
  async function worker() {
    while (i < N) {
      i++
      try {
        ok += await issueOne()
      } catch (e) {
        if (!firstErr) firstErr = e
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker))
  if (ok < N && firstErr) console.log('  first error:', (firstErr as Error).message)
  const d = (Date.now() - t0) / 1000
  console.log(
    `  issued ${ok}/${N} SD-JWT credentials in ${d.toFixed(2)}s = ${(ok / d).toFixed(1)} creds/s (full OID4VCI HTTP path, Credo ${CREDO_VERSION})`,
  )

  server.close()
  await agent.shutdown()
  process.exit(0)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
