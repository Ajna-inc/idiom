import axios, { type AxiosInstance } from 'axios'

export interface InvitationConfig {
  label?: string
  multiUse?: boolean
  autoAcceptConnection?: boolean
}

export class RustClient {
  private client: AxiosInstance

  constructor(baseUrl = 'http://localhost:3002') {
    this.client = axios.create({
      baseURL: baseUrl,
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    })
  }

  /**
   * Create an Out-of-Band invitation
   */
  async createOobInvitation(config?: InvitationConfig) {
    const { data } = await this.client.post('/oob/create-invitation', config || {})
    return data
  }

  /**
   * Receive an Out-of-Band invitation
   */
  async receiveOobInvitation(invitation: any) {
    const { data } = await this.client.post('/oob/receive-invitation', { invitation })
    return data
  }

  /**
   * Get all connections
   */
  async getConnections() {
    const { data } = await this.client.get('/connections')
    return data
  }

  /**
   * Get a specific connection by ID
   */
  async getConnection(id: string) {
    const { data } = await this.client.get(`/connections/${id}`)
    return data
  }

  /**
   * Get all Out-of-Band records
   */
  async getOobRecords() {
    const { data } = await this.client.get('/oob/records')
    return data
  }

  /**
   * Send a basic message
   */
  async sendBasicMessage(connectionId: string, content: string, parentThreadId?: string) {
    const { data } = await this.client.post('/basic-messages/send', {
      connectionId,
      content,
      parentThreadId,
    })
    return data
  }

  /**
   * Get all basic messages for a connection
   */
  async getBasicMessages(connectionId: string) {
    const { data } = await this.client.get('/basic-messages', {
      params: { connectionId },
    })
    return data
  }

  /**
   * Health check
   */
  async health() {
    const { data } = await this.client.get('/health')
    return data
  }
}
