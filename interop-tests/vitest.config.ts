import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    // Interop runs against a single shared mediator pickup queue, so test
    // FILES must run one-at-a-time — parallel files create competing
    // connections that starve each other's pickup delivery.
    fileParallelism: false,
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    // Mediator pickup adds multi-second latency per DIDComm round-trip, and a
    // full DID-Exchange is several round-trips, so give generous budgets.
    testTimeout: 150000,
    hookTimeout: 150000,
    teardownTimeout: 15000,
  },
})
