import WebSocket from 'ws'
import EventSource from 'eventsource'
import type { ObservedEvent, EventPredicate } from './types'

/**
 * EventObserver connects to both Credo and Rust agents' event streams
 * and collects all events for testing and assertions.
 *
 * - Credo: WebSocket on ws://localhost:9000
 * - Rust: Server-Sent Events on http://localhost:3002/events
 */
export class EventObserver {
  private events: ObservedEvent[] = []
  private credoWs?: WebSocket
  private rustEventSource?: EventSource
  private connected = false

  /**
   * Connect to both agents' event streams
   */
  async connect(credoWsUrl = 'ws://localhost:9000', rustSseUrl = 'http://localhost:3002/events'): Promise<void> {
    return new Promise((resolve, reject) => {
      let credoReady = false
      let rustReady = false

      const checkReady = () => {
        if (credoReady && rustReady) {
          this.connected = true
          resolve()
        }
      }

      // Connect to Credo WebSocket
      this.credoWs = new WebSocket(credoWsUrl)

      this.credoWs.on('open', () => {
        console.log('✓ Connected to Credo event stream (WebSocket)')
        credoReady = true
        checkReady()
      })

      this.credoWs.on('message', (data: Buffer) => {
        try {
          const event = JSON.parse(data.toString())
          this.events.push({
            agent: 'credo',
            timestamp: event.timestamp || Date.now(),
            type: event.type,
            payload: event.payload,
          })
        } catch (error) {
          console.error('Error parsing Credo event:', error)
        }
      })

      this.credoWs.on('error', (error) => {
        console.error('Credo WebSocket error:', error)
        reject(error)
      })

      // Connect to Rust Server-Sent Events
      this.rustEventSource = new EventSource(rustSseUrl)

      this.rustEventSource.onopen = () => {
        console.log('✓ Connected to Rust event stream (SSE)')
        rustReady = true
        checkReady()
      }

      this.rustEventSource.onmessage = (e: MessageEvent) => {
        try {
          const event = JSON.parse(e.data)
          // The agent emits a split { topic, event_type, payload } envelope,
          // where payload is the typed struct (e.g. { connection_record },
          // { record }). Normalize to the shape the tests assert against:
          //   type    = "<topic>.<event_type>" (e.g. connection.state_changed)
          //   payload = the inner record flattened to the top level, so fields
          //             like state/id/connection_id/role/content are directly
          //             readable (nested form is preserved too).
          const type = event.event_type
            ? `${event.topic}.${event.event_type}`
            : event.topic
          let payload = event.payload ?? {}
          if (payload && typeof payload === 'object') {
            const inner = payload.connection_record ?? payload.record
            if (inner && typeof inner === 'object') {
              payload = { ...payload, ...inner }
            }
          }
          this.events.push({
            agent: 'rust',
            timestamp: event.timestamp || Date.now(),
            type,
            payload,
          })
        } catch (error) {
          console.error('Error parsing Rust event:', error)
        }
      }

      this.rustEventSource.onerror = (error) => {
        console.error('Rust EventSource error:', error)
        // Don't reject immediately, might be transient
      }

      // Timeout if connection takes too long
      setTimeout(() => {
        if (!this.connected) {
          reject(new Error('Timeout connecting to event streams'))
        }
      }, 10000)
    })
  }

  /**
   * Get all events collected so far, sorted by timestamp
   */
  getEvents(): ObservedEvent[] {
    return [...this.events].sort((a, b) => a.timestamp - b.timestamp)
  }

  /**
   * Get events from a specific agent
   */
  getEventsByAgent(agent: 'credo' | 'rust'): ObservedEvent[] {
    return this.events.filter(e => e.agent === agent).sort((a, b) => a.timestamp - b.timestamp)
  }

  /**
   * Find the first event matching a predicate
   */
  findEvent(predicate: EventPredicate): ObservedEvent | undefined {
    return this.events.find(predicate)
  }

  /**
   * Wait for an event matching a predicate
   * Polls every 100ms until the event is found or timeout is reached
   */
  async waitForEvent(predicate: EventPredicate, timeoutMs = 30000): Promise<ObservedEvent> {
    const start = Date.now()

    while (Date.now() - start < timeoutMs) {
      const event = this.findEvent(predicate)
      if (event) {
        return event
      }
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    // Helpful error message with recent events
    const recentEvents = this.events.slice(-10).map(e => `  [${e.agent}] ${e.type}`)
    throw new Error(
      `Timeout waiting for event after ${timeoutMs}ms.\n\nRecent events:\n${recentEvents.join('\n')}`
    )
  }

  /**
   * Wait for multiple events in sequence
   */
  async waitForSequence(predicates: EventPredicate[], timeoutMs = 30000): Promise<ObservedEvent[]> {
    const results: ObservedEvent[] = []

    for (const predicate of predicates) {
      const event = await this.waitForEvent(predicate, timeoutMs)
      results.push(event)
    }

    return results
  }

  /**
   * Clear all collected events
   */
  clear() {
    this.events = []
  }

  /**
   * Print event timeline for debugging
   */
  printTimeline() {
    console.log('\n📊 Event Timeline:')
    console.log('─'.repeat(80))

    const sortedEvents = this.getEvents()
    if (sortedEvents.length === 0) {
      console.log('  (no events captured)')
      return
    }

    const startTime = sortedEvents[0].timestamp
    sortedEvents.forEach(e => {
      const elapsed = ((e.timestamp - startTime) / 1000).toFixed(2)
      console.log(`  +${elapsed}s [${e.agent.padEnd(5)}] ${e.type}`)
    })

    console.log('─'.repeat(80))
    console.log(`Total events: ${sortedEvents.length}\n`)
  }

  /**
   * Disconnect from event streams
   */
  disconnect() {
    this.credoWs?.close()
    this.rustEventSource?.close()
    this.connected = false
  }

  isConnected(): boolean {
    return this.connected
  }
}
