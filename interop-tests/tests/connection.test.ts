import { describe, test, beforeAll, afterAll, expect, beforeEach } from 'vitest'
import { CredoClient } from '../src/clients/CredoClient'
import { RustClient } from '../src/clients/RustClient'
import { EventObserver } from '../src/observers/EventObserver'

/**
 * Interoperability Tests: Credo ↔ Rust Connection Flow
 *
 * These tests verify that Credo-TS and Rust agents can establish
 * DIDComm connections with each other using the DID Exchange protocol.
 *
 * Prerequisites:
 *   - Run `npm run agents:start` before running tests
 *   - Both agents must be running and healthy
 */

describe('Interop: Credo ↔ Rust Connection', () => {
  let credoClient: CredoClient
  let rustClient: RustClient
  let observer: EventObserver

  beforeAll(async () => {
    console.log('\n🚀 Connecting to running agents...\n')

    // Create HTTP clients
    credoClient = new CredoClient()
    rustClient = new RustClient()

    // Verify agents are running and healthy
    console.log('  Checking Credo agent...')
    try {
      await credoClient.health()
      console.log('  ✓ Credo agent ready')
    } catch (error) {
      throw new Error(
        'Credo agent is not running. Please start it with: npm run agents:start'
      )
    }

    console.log('  Checking Rust agent...')
    try {
      await rustClient.health()
      console.log('  ✓ Rust agent ready')
    } catch (error) {
      throw new Error(
        'Rust agent is not running. Please start it with: npm run agents:start'
      )
    }

    // Create event observer
    observer = new EventObserver()
    await observer.connect()

    console.log('\n✅ All systems ready for testing!\n')
  }, 30000)

  beforeEach(() => {
    // Clear events before each test
    observer.clear()
  })

  afterAll(async () => {
    console.log('\n✓ Tests completed. Disconnecting event observer...\n')
    observer.disconnect()
    // Note: Agents are left running. Stop them with: npm run agents:stop
  })

  test('Credo inviter → Rust invitee connection', async () => {
    console.log('\n📋 Test: Credo inviter → Rust invitee\n')

    // Clear any previous events
    observer.clear()

    // Step 1: Alice (Credo) creates invitation
    console.log('  1. Alice (Credo) creates OOB invitation...')
    const aliceOob = await credoClient.createOobInvitation({
      label: 'Alice',
    })

    console.log(`     ✓ Invitation created: ${aliceOob.id}`)

    // Wait for Credo invitation created event
    await observer.waitForEvent(
      e => e.agent === 'credo' && e.type.includes('OutOfBand') && e.payload.outOfBandRecord?.id === aliceOob.id
    )
    console.log('     ✓ Credo emitted OutOfBand event')

    // Step 2: Bob (Rust) receives invitation
    console.log('\n  2. Bob (Rust) receives invitation...')
    const bobResult = await rustClient.receiveOobInvitation(aliceOob.invitation)

    console.log(`     ✓ Rust received invitation: ${bobResult.id}`)

    // Step 3: Wait for both connections to complete
    console.log('\n  3. Waiting for connections to complete...')

    const credoCompletedEvent = await observer.waitForEvent(
      e =>
        e.agent === 'credo' &&
        e.type === 'ConnectionStateChanged' &&
        e.payload.connectionRecord?.state === 'completed',
      60000
    )
    console.log('     ✓ Credo connection completed')

    const rustCompletedEvent = await observer.waitForEvent(
      e => e.agent === 'rust' && e.type === 'connection.state_changed' && e.payload.state === 'Completed',
      60000
    )
    console.log('     ✓ Rust connection completed')

    // Step 4: Verify final connection states
    console.log('\n  4. Verifying connection states...')

    // Use the connection IDs from the completion events
    const credoConnId = credoCompletedEvent.payload.connectionRecord?.id
    const rustConnId = rustCompletedEvent.payload.id

    const credoConnections = await credoClient.getConnections()
    const rustConnections = await rustClient.getConnections()

    const credoConn = credoConnections.find(c => c.id === credoConnId)
    const rustConn = rustConnections.find(c => c.id === rustConnId)

    expect(credoConn).toBeDefined()
    expect(rustConn).toBeDefined()

    // Verify states
    expect(credoConn.state).toBe('completed')
    expect(rustConn.state).toBe('Completed')
    console.log('     ✓ Both connections in completed state')

    // Verify DID pairing
    expect(credoConn.theirDid).toBe(rustConn.did)
    expect(rustConn.theirDid).toBe(credoConn.did)
    console.log('     ✓ DIDs properly paired')

    // Print event timeline
    console.log('\n📊 Event Timeline:')
    observer.printTimeline()

    console.log('✅ Test passed! Credo and Rust successfully connected.\n')
  }, 120000)

  test('Rust inviter → Credo invitee connection', async () => {
    console.log('\n📋 Test: Rust inviter → Credo invitee\n')

    observer.clear()

    // Step 1: Bob (Rust) creates invitation
    console.log('  1. Bob (Rust) creates OOB invitation...')
    const bobOob = await rustClient.createOobInvitation({
      label: 'Bob',
    })

    console.log(`     ✓ Invitation created: ${bobOob.id}`)

    // Step 2: Alice (Credo) receives invitation
    console.log('\n  2. Alice (Credo) receives invitation...')
    const aliceResult = await credoClient.receiveOobInvitation(bobOob.invitation)

    console.log(`     ✓ Credo received invitation: ${aliceResult.id}`)

    // Step 3: Wait for both connections to complete
    console.log('\n  3. Waiting for connections to complete...')

    const credoCompletedEvent = await observer.waitForEvent(
      e =>
        e.agent === 'credo' &&
        e.type === 'ConnectionStateChanged' &&
        e.payload.connectionRecord?.state === 'completed',
      60000
    )
    console.log('     ✓ Credo connection completed')

    const rustCompletedEvent = await observer.waitForEvent(
      e => e.agent === 'rust' && e.type === 'connection.state_changed' && e.payload.state === 'Completed',
      60000
    )
    console.log('     ✓ Rust connection completed')

    // Step 4: Verify final connection states
    console.log('\n  4. Verifying connection states...')

    // Use the connection IDs from the completion events
    const credoConnId = credoCompletedEvent.payload.connectionRecord?.id
    const rustConnId = rustCompletedEvent.payload.id

    const credoConnections = await credoClient.getConnections()
    const rustConnections = await rustClient.getConnections()

    const credoConn = credoConnections.find(c => c.id === credoConnId)
    const rustConn = rustConnections.find(c => c.id === rustConnId)

    expect(credoConn).toBeDefined()
    expect(rustConn).toBeDefined()

    expect(credoConn.state).toBe('completed')
    expect(rustConn.state).toBe('Completed')
    console.log('     ✓ Both connections in completed state')

    expect(credoConn.theirDid).toBe(rustConn.did)
    expect(rustConn.theirDid).toBe(credoConn.did)
    console.log('     ✓ DIDs properly paired')

    observer.printTimeline()

    console.log('✅ Test passed! Rust and Credo successfully connected.\n')
  }, 120000)
})
