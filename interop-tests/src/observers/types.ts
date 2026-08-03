export interface ObservedEvent {
  agent: 'credo' | 'rust'
  timestamp: number
  type: string
  payload: any
}

export type EventPredicate = (event: ObservedEvent) => boolean
