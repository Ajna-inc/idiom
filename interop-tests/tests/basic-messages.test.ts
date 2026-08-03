import { describe, test, beforeAll, afterAll, expect, beforeEach } from 'vitest'
import { CredoClient } from '../src/clients/CredoClient'
import { RustClient } from '../src/clients/RustClient'
import { EventObserver } from '../src/observers/EventObserver'

/**
 * Interoperability Tests: Credo ↔ Rust Basic Messages
 *
 * These tests verify that Credo-TS and Rust agents can send and receive
 * basic text messages bidirectionally over established DIDComm connections.
 *
 * Prerequisites:
 *   - Run `npm run agents:start` before running tests
 *   - Both agents must be running and healthy
 *   - Must have an established connection between agents
 */

describe('Interop: Credo ↔ Rust Basic Messages', () => {
  let credoClient: CredoClient
  let rustClient: RustClient
  let observer: EventObserver
  let credoConnectionId: string
  let rustConnectionId: string

  beforeAll(async () => {
    console.log('\n🚀 Setting up agents for basic messages tests...\n')

    // Create HTTP clients
    credoClient = new CredoClient()
    rustClient = new RustClient()

    // Verify agents are running
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

    // Establish a connection first
    console.log('\n  Setting up connection for messages...')
    observer.clear()

    // Create invitation from Credo
    const credoOob = await credoClient.createOobInvitation({ label: 'Alice' })

    // Rust receives and accepts
    const rustResult = await rustClient.receiveOobInvitation(credoOob.invitation)

    // Wait for both connections to complete
    const credoCompletedEvent = await observer.waitForEvent(
      e =>
        e.agent === 'credo' &&
        e.type === 'ConnectionStateChanged' &&
        e.payload.connectionRecord?.state === 'completed',
      60000
    )

    const rustCompletedEvent = await observer.waitForEvent(
      e => e.agent === 'rust' && e.type === 'connection.state_changed' && e.payload.state === 'Completed',
      60000
    )

    credoConnectionId = credoCompletedEvent.payload.connectionRecord?.id
    rustConnectionId = rustCompletedEvent.payload.id

    console.log(`  ✓ Connection established`)
    console.log(`     Credo connection: ${credoConnectionId}`)
    console.log(`     Rust connection: ${rustConnectionId}`)

    console.log('\n✅ All systems ready for messaging tests!\n')
  }, 90000)

  beforeEach(() => {
    // Clear events before each test
    observer.clear()
  })

  afterAll(async () => {
    console.log('\n✓ Tests completed. Disconnecting event observer...\n')
    observer.disconnect()
  })

  test('Rust → Credo basic message', async () => {
    console.log('\n📋 Test: Rust sends basic message to Credo\n')

    observer.clear()

    const messageContent = 'Hello from Rust! 🦀'

    // Step 1: Rust sends message
    console.log(`  1. Rust sending message: "${messageContent}"`)
    const rustRecord = await rustClient.sendBasicMessage(rustConnectionId, messageContent)

    console.log(`     ✓ Message sent with ID: ${rustRecord.id}`)
    expect(rustRecord.content).toBe(messageContent)
    expect(rustRecord.connection_id).toBe(rustConnectionId)
    expect(rustRecord.role).toBe('sender')

    // Step 2: Wait for Credo to receive the message event
    console.log('\n  2. Waiting for Credo to receive message...')

    const credoReceivedEvent = await observer.waitForEvent(
      e =>
        e.agent === 'credo' &&
        e.type === 'BasicMessageStateChanged' &&
        e.payload.basicMessageRecord?.connectionId === credoConnectionId &&
        e.payload.basicMessageRecord?.role === 'receiver',
      30000
    )

    console.log('     ✓ Credo received basic message event')

    // Step 3: Verify message in Credo's storage
    console.log('\n  3. Verifying message content in Credo...')

    await new Promise(resolve => setTimeout(resolve, 1000)) // Brief wait for storage

    const credoMessages = await credoClient.getBasicMessages(credoConnectionId)
    const receivedMessage = credoMessages.find(
      m => m.role === 'receiver' && m.content === messageContent
    )

    expect(receivedMessage).toBeDefined()
    expect(receivedMessage.content).toBe(messageContent)
    expect(receivedMessage.connectionId).toBe(credoConnectionId)
    expect(receivedMessage.role).toBe('receiver')

    console.log(`     ✓ Message verified: "${receivedMessage.content}"`)
    console.log(`     ✓ Message ID: ${receivedMessage.id}`)

    console.log('\n✅ Test passed! Rust→Credo messaging works correctly.\n')
  }, 60000)

  test('Credo → Rust basic message', async () => {
    console.log('\n📋 Test: Credo sends basic message to Rust\n')

    observer.clear()

    const messageContent = 'Hello from Credo! 🚀'

    // Step 1: Credo sends message
    console.log(`  1. Credo sending message: "${messageContent}"`)
    const credoRecord = await credoClient.sendBasicMessage(credoConnectionId, messageContent)

    console.log(`     ✓ Message sent with ID: ${credoRecord.id}`)
    expect(credoRecord.content).toBe(messageContent)
    expect(credoRecord.connectionId).toBe(credoConnectionId)
    expect(credoRecord.role).toBe('sender')

    // Step 2: Wait for Rust to receive the message event
    console.log('\n  2. Waiting for Rust to receive message...')

    const rustReceivedEvent = await observer.waitForEvent(
      e =>
        e.agent === 'rust' &&
        e.type === 'basic_message.state_changed' &&
        e.payload.connection_id === rustConnectionId &&
        e.payload.role === 'receiver',
      30000
    )

    console.log('     ✓ Rust received basic message event')

    // Step 3: Verify message in Rust's storage
    console.log('\n  3. Verifying message content in Rust...')

    await new Promise(resolve => setTimeout(resolve, 1000)) // Brief wait for storage

    const rustMessages = await rustClient.getBasicMessages(rustConnectionId)
    const receivedMessage = rustMessages.find(
      m => m.role === 'receiver' && m.content === messageContent
    )

    expect(receivedMessage).toBeDefined()
    expect(receivedMessage.content).toBe(messageContent)
    expect(receivedMessage.connection_id).toBe(rustConnectionId)
    expect(receivedMessage.role).toBe('receiver')

    console.log(`     ✓ Message verified: "${receivedMessage.content}"`)
    console.log(`     ✓ Message ID: ${receivedMessage.id}`)

    console.log('\n✅ Test passed! Credo→Rust messaging works correctly.\n')
  }, 60000)

  test('Bidirectional conversation', async () => {
    console.log('\n📋 Test: Bidirectional conversation\n')

    observer.clear()

    // Step 1: Rust sends first message
    console.log('  1. Rust sends: "Question: What is DIDComm?"')
    const rustMsg1 = await rustClient.sendBasicMessage(
      rustConnectionId,
      'Question: What is DIDComm?'
    )

    await observer.waitForEvent(
      e =>
        e.agent === 'credo' &&
        e.type === 'BasicMessageStateChanged' &&
        e.payload.basicMessageRecord?.role === 'receiver',
      30000
    )
    console.log('     ✓ Credo received')

    // Step 2: Credo replies
    console.log('\n  2. Credo replies: "Answer: Decentralized Identity Communication protocol!"')
    const credoMsg1 = await credoClient.sendBasicMessage(
      credoConnectionId,
      'Answer: Decentralized Identity Communication protocol!'
    )

    await observer.waitForEvent(
      e =>
        e.agent === 'rust' &&
        e.type === 'basic_message.state_changed' &&
        e.payload.role === 'receiver',
      30000
    )
    console.log('     ✓ Rust received')

    // Step 3: Rust sends another message
    console.log('\n  3. Rust sends: "Thanks for the explanation! 🎉"')
    const rustMsg2 = await rustClient.sendBasicMessage(
      rustConnectionId,
      'Thanks for the explanation! 🎉'
    )

    await observer.waitForEvent(
      e =>
        e.agent === 'credo' &&
        e.type === 'BasicMessageStateChanged' &&
        e.payload.basicMessageRecord?.role === 'receiver' &&
        e.payload.basicMessageRecord?.content?.includes('Thanks'),
      30000
    )
    console.log('     ✓ Credo received')

    // Step 4: Verify full conversation in both agents
    console.log('\n  4. Verifying full conversation history...')

    await new Promise(resolve => setTimeout(resolve, 1500))

    const credoMessages = await credoClient.getBasicMessages(credoConnectionId)
    const rustMessages = await rustClient.getBasicMessages(rustConnectionId)

    // Credo should have: 1 sent, 2 received
    const credoSent = credoMessages.filter(m => m.role === 'sender')
    const credoReceived = credoMessages.filter(m => m.role === 'receiver')

    // Rust should have: 2 sent, 1 received
    const rustSent = rustMessages.filter(m => m.role === 'sender')
    const rustReceived = rustMessages.filter(m => m.role === 'receiver')

    console.log(`     Credo: ${credoSent.length} sent, ${credoReceived.length} received`)
    console.log(`     Rust:  ${rustSent.length} sent, ${rustReceived.length} received`)

    expect(credoSent.length).toBeGreaterThanOrEqual(1)
    expect(credoReceived.length).toBeGreaterThanOrEqual(2)
    expect(rustSent.length).toBeGreaterThanOrEqual(2)
    expect(rustReceived.length).toBeGreaterThanOrEqual(1)

    // Verify exact content
    expect(credoReceived.some(m => m.content === 'Question: What is DIDComm?')).toBe(true)
    expect(credoReceived.some(m => m.content.includes('Thanks'))).toBe(true)
    expect(rustReceived.some(m => m.content.includes('Decentralized Identity'))).toBe(true)

    console.log('     ✓ Full conversation verified on both sides')

    // Print timeline
    console.log('\n📊 Event Timeline:')
    observer.printTimeline()

    console.log('\n✅ Test passed! Bidirectional conversation works correctly.\n')
  }, 90000)
})
