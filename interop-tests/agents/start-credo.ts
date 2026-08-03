import {
  Agent,
  ConnectionsModule,
  HttpOutboundTransport,
  WsOutboundTransport,
  ConnectionEventTypes,
  ConnectionStateChangedEvent,
  OutOfBandEventTypes,
  CredentialEventTypes,
  ProofEventTypes,
  LogLevel,
  ConsoleLogger,
  BasicMessageEventTypes,
  MediationRecipientModule,
  MediatorPickupStrategy,
} from '@credo-ts/core'
import { BasicMessagesModule } from '@credo-ts/core'
import { AskarModule } from '@credo-ts/askar'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { agentDependencies, HttpInboundTransport } from '@credo-ts/node'
// import { WebRTCModule, WebRTCEvents } from '@ajna-inc/webrtc'
// import { WorkflowModule, WorkflowEventTypes } from '@ajna-inc/workflow'
import express from 'express'
import WebSocket from 'ws'

/**
 * Standalone Credo agent with HTTP API and WebSocket event stream
 *
 * HTTP API: http://localhost:3000
 * DIDComm endpoint: http://localhost:3001
 * WebSocket Events: ws://localhost:9000
 */

console.log('🚀 Starting Credo Agent...\n')

// Live mediator. Prefer the injected invite (run-interop.sh fetches a fresh
// one per agent); otherwise fetch a fresh invitation from the live mediator.
// (The old hardcoded 68.183.244.145 invite is dead — never reintroduce it.)
const MEDIATOR_INVITE_ENDPOINT =
  process.env.MEDIATOR_INVITE_ENDPOINT || 'https://mediator.ajna.surf/invite'

async function fetchMediatorInvite(): Promise<string | undefined> {
  const res = await fetch(MEDIATOR_INVITE_ENDPOINT)
  const body = (await res.json()) as { invitationUrl?: string }
  return body.invitationUrl
}

const MEDIATOR_URL =
  process.env.MEDIATOR_INVITATION_URL || (await fetchMediatorInvite())

if (!MEDIATOR_URL) {
  throw new Error(`Could not obtain a mediator invitation from ${MEDIATOR_INVITE_ENDPOINT}`)
}

console.log(`📡 Mediator: ${MEDIATOR_URL.substring(0, 60)}...`)

// ===== Create Agent with Full Production Setup =====
const agent = new Agent({
  config: {
    label: 'Credo Interop Agent',
    walletConfig: {
      id: `credo-interop-wallet-${Date.now()}`,
      key: 'test-wallet-key-12345678',
    },
    // No direct endpoint — all messages routed through mediator
    endpoints: [],
    logger: new ConsoleLogger(LogLevel.debug),
  },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({
      ariesAskar,
    }),
    connections: new ConnectionsModule({
      autoAcceptConnections: true,
    }),
    basicMessages: new BasicMessagesModule(),
    mediationRecipient: new MediationRecipientModule({
      mediatorInvitationUrl: MEDIATOR_URL,
    }),
  },
})

// No inbound transport — messages arrive via mediator pickup
agent.registerOutboundTransport(new HttpOutboundTransport())
agent.registerOutboundTransport(new WsOutboundTransport())

// Initialize agent
await agent.initialize()

console.log('✓ Credo agent initialized')
console.log(`  Label: ${agent.config.label}`)
console.log(`  DIDComm endpoint: http://localhost:3001\n`)

// ===== HTTP API Server =====
const app = express()
app.use(express.json())

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', label: agent.config.label })
})

// Create Out-of-Band invitation
app.post('/oob/create-invitation', async (req, res) => {
  try {
    console.log('[API] POST /oob/create-invitation', req.body)

    const config = req.body || {}
    const record = await agent.oob.createInvitation(config)

    // Generate invitation URL
    const invitationUrl = record.outOfBandInvitation.toUrl({ domain: 'https://example.org' })

    console.log(`✓ Created OOB invitation: ${record.id}`)

    res.json({
      id: record.id,
      invitation: record.outOfBandInvitation,
      invitationUrl,
      outOfBandRecord: record,
    })
  } catch (error: any) {
    console.error('[ERROR] creating invitation:', error.message)
    console.error('[ERROR] stack:', error.stack)
    res.status(500).json({ error: error.message })
  }
})

// Receive Out-of-Band invitation
app.post('/oob/receive-invitation', async (req, res) => {
  try {
    console.log('[API] POST /oob/receive-invitation')
    const { invitation, invitationUrl } = req.body

    if (!invitation && !invitationUrl) {
      return res.status(400).json({ error: 'Missing invitation or invitationUrl in request body' })
    }

    let result

    if (invitationUrl) {
      // Receive from URL
      console.log('[DEBUG] Receiving invitation from URL:', invitationUrl)
      result = await agent.oob.receiveInvitationFromUrl(invitationUrl)
    } else {
      // Receive from invitation object - need to convert to URL first
      console.log('[DEBUG] Converting invitation object to URL')
      const invitationMessage = invitation

      // Create a temporary URL with the invitation data
      const invitationString = JSON.stringify(invitationMessage)
      const base64Invitation = Buffer.from(invitationString).toString('base64url')
      const url = `https://example.org?oob=${base64Invitation}`

      console.log('[DEBUG] Generated URL for invitation')
      result = await agent.oob.receiveInvitationFromUrl(url)
    }

    console.log(`✓ Received OOB invitation: ${result.outOfBandRecord.id}`)

    res.json({
      id: result.outOfBandRecord.id,
      outOfBandRecord: result.outOfBandRecord,
      connectionRecord: result.connectionRecord,
    })
  } catch (error: any) {
    console.error('[ERROR] receiving invitation:', error.message)
    console.error('[ERROR] stack:', error.stack)
    res.status(500).json({ error: error.message })
  }
})

// Get all connections
app.get('/connections', async (_req, res) => {
  try {
    const connections = await agent.connections.getAll()
    res.json(connections)
  } catch (error: any) {
    console.error('Error getting connections:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// Get specific connection
app.get('/connections/:id', async (req, res) => {
  try {
    const connection = await agent.connections.getById(req.params.id)
    res.json(connection)
  } catch (error: any) {
    console.error('Error getting connection:', error.message)
    res.status(404).json({ error: 'Connection not found' })
  }
})

// Get all OOB records
app.get('/oob/records', async (_req, res) => {
  try {
    const records = await agent.oob.getAll()
    res.json(records)
  } catch (error: any) {
    console.error('Error getting OOB records:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// Send a basic message
app.post('/basic-messages/send', async (req, res) => {
  try {
    console.log('[API] POST /basic-messages/send', req.body)
    const { connectionId, content, parentThreadId } = req.body

    if (!connectionId || !content) {
      return res.status(400).json({ error: 'Missing connectionId or content in request body' })
    }

    const record = await agent.basicMessages.sendMessage(connectionId, content)

    console.log(`✓ Sent basic message: ${record.id}`)

    res.json(record)
  } catch (error: any) {
    console.error('[ERROR] sending basic message:', error.message)
    res.status(500).json({ error: error.message })
  }
})

// Get all basic messages for a connection
app.get('/basic-messages', async (req, res) => {
  try {
    const { connectionId } = req.query

    if (!connectionId || typeof connectionId !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid connectionId query parameter' })
    }

    // Use findAllByQuery with connectionId filter
    const messages = await agent.basicMessages.findAllByQuery({ connectionId })

    res.json(messages)
  } catch (error: any) {
    console.error('[ERROR] getting basic messages:', error.message)
    res.status(500).json({ error: error.message })
  }
})

const HTTP_PORT = 3000
app.listen(HTTP_PORT, () => {
  console.log(`✓ HTTP API listening on http://localhost:${HTTP_PORT}`)
})

// ===== WebSocket Event Stream =====
const WS_PORT = 9000
const wss = new WebSocket.Server({ port: WS_PORT })

console.log(`✓ WebSocket event stream on ws://localhost:${WS_PORT}`)

wss.on('connection', (ws) => {
  console.log('  → New event stream client connected')

  ws.on('close', () => {
    console.log('  ← Event stream client disconnected')
  })
})

// Helper to broadcast event to WebSocket clients
const broadcastEvent = (type: string, payload: any) => {
  console.log(`[EVENT] ${type}`, {
    payload: JSON.stringify(payload, null, 2).substring(0, 300)
  })

  const message = JSON.stringify({
    timestamp: Date.now(),
    type,
    payload,
  })

  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message)
    }
  })
}

// Subscribe to specific event types with proper typing
console.log('📡 Setting up event listeners...')

// Connection events
agent.events.on<ConnectionStateChangedEvent>(
  ConnectionEventTypes.ConnectionStateChanged,
  ({ payload }) => {
    console.log(`[CONNECTION STATE] ${payload.previousState} → ${payload.connectionRecord.state}`)
    broadcastEvent(ConnectionEventTypes.ConnectionStateChanged, payload)
  }
)

// Out-of-Band events
agent.events.on(OutOfBandEventTypes.OutOfBandStateChanged, ({ payload }) => {
  console.log(`[OOB STATE] ${payload.outOfBandRecord.state}`)
  broadcastEvent(OutOfBandEventTypes.OutOfBandStateChanged, payload)
})

agent.events.on(OutOfBandEventTypes.HandshakeReused, ({ payload }) => {
  console.log(`[OOB] Handshake reused`)
  broadcastEvent(OutOfBandEventTypes.HandshakeReused, payload)
})

// Basic Message events
agent.events.on(BasicMessageEventTypes.BasicMessageStateChanged, ({ payload }) => {
  console.log(`[BASIC MESSAGE] ${payload.basicMessageRecord.role} - ${payload.basicMessageRecord.content?.substring(0, 50)}...`)
  broadcastEvent(BasicMessageEventTypes.BasicMessageStateChanged, payload)
})

// WebRTC and Workflow event listeners removed for connection testing

// Also subscribe to wildcard for ALL events to catch everything
agent.events.on('*', (event: any) => {
  const eventType = event.type || 'unknown'

  // Log ALL events with full details for debugging
  console.log(`[EVENT] ${eventType}`)

  // Try to extract useful info from payload
  if (event.payload) {
    const payload = event.payload

    // Check if it's a message-related event
    if (payload.message) {
      console.log(`  Message type: ${payload.message['@type'] || payload.message.type || 'unknown'}`)
      console.log(`  Message ID: ${payload.message['@id'] || payload.message.id || 'unknown'}`)
    }

    // Check if there's an error
    if (payload.error) {
      console.error(`  ⚠️ Event contains error:`, payload.error)
    }

    // Check for connection/record IDs
    if (payload.connectionRecord?.id) {
      console.log(`  Connection ID: ${payload.connectionRecord.id}`)
    }
    if (payload.outOfBandRecord?.id) {
      console.log(`  OOB Record ID: ${payload.outOfBandRecord.id}`)
    }
  }
})

console.log('✓ Event listeners configured')

console.log('\n✅ Credo agent ready for interop testing!\n')

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n\n🛑 Shutting down Credo agent...')
  wss.close()
  await agent.shutdown()
  console.log('✓ Credo agent shut down\n')
  process.exit(0)
})
