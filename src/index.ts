import { base64UrlDecode, base64UrlEncode } from './codec'

export type LocalSecretStateSyncConfig<StateType> = {
  encryptionKey: string
  onStateUpdated: (newState: StateType) => unknown
  stateParser?: Parser<StateType>
  stateSerializer?: Serializer<StateType>
}

type Parser<T> = (input: string) => T
type Serializer<T> = (input: T) => string

type IdleInternalState = {
  state: 'idle'
}
type LoadedInternalState = {
  state: 'loaded'
  storageKey: string
  encryptionKey: CryptoKey
}
type InternalState = IdleInternalState | LoadedInternalState

export class LocalSecretStateSync<StateType> {
  #internalState: InternalState
  private config: Required<
    Omit<LocalSecretStateSyncConfig<StateType>, 'encryptionKey'>
  >

  constructor({
    encryptionKey,
    ...config
  }: LocalSecretStateSyncConfig<StateType>) {
    this.#internalState = {
      state: 'idle'
    }
    this.config = {
      ...config,
      stateParser: config.stateParser ?? JSON.parse,
      stateSerializer: config.stateSerializer ?? JSON.stringify
    }
    this.setup(encryptionKey).then(this.loadFromLocalStorage.bind(this))
  }

  public async setState(state: StateType) {
    if (typeof window === 'undefined') {
      console.warn('LocalSecretStateSync is disabled in Node.js')
      return
    }
    if (this.#internalState.state !== 'loaded') {
      throw new Error('LocalSecretStateSync is not ready')
    }
    const encryptedState = await this.encryptState(state)
    window.localStorage.setItem(this.#internalState.storageKey, encryptedState)
  }

  public clearState() {
    if (typeof window === 'undefined') {
      console.warn('LocalSecretStateSync is disabled in Node.js')
      return
    }
    if (this.#internalState.state !== 'loaded') {
      throw new Error('LocalSecretStateSync is not ready')
    }
    window.localStorage.removeItem(this.#internalState.storageKey)
  }

  private async setup(encodedEncryptionKey: string) {
    const keyBuffer = base64UrlDecode(encodedEncryptionKey)
    if (keyBuffer.byteLength !== 32) {
      throw new Error(
        'LocalSecretStateSync: encryptionKey must be 32 bytes (48 base64url characters)'
      )
    }
    if (typeof window === 'undefined') {
      console.warn('LocalSecretStateSync is disabled in Node.js')
      return
    }
    const encryptionKey = await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt', 'decrypt']
    )
    const storageKey = base64UrlEncode(
      new Uint8Array(await window.crypto.subtle.digest('SHA-256', keyBuffer))
    )
    this.#internalState = {
      state: 'loaded',
      storageKey,
      encryptionKey
    }
    addEventListener('storage', this.handleStorageEvent.bind(this))
  }

  private async loadFromLocalStorage() {
    if (this.#internalState.state !== 'loaded') {
      return
    }
    const value = window.localStorage.getItem(this.#internalState.storageKey)
    if (!value) {
      return
    }
    try {
      const state = await this.decryptState(value)
      this.config.onStateUpdated(state)
    } catch {}
  }

  private async handleStorageEvent(event: StorageEvent) {
    if (this.#internalState.state !== 'loaded') {
      return // Not ready
    }
    if (event.key !== this.#internalState.storageKey || !event.newValue) {
      return
    }
    try {
      const state = await this.decryptState(event.newValue)
      this.config.onStateUpdated(state)
    } catch {}
  }

  // --

  private async decryptState(storageValue: string) {
    if (this.#internalState.state !== 'loaded') {
      throw new Error('LocalSecretStateSync is not ready')
    }
    const [iv, ciphertext] = storageValue.split('.')
    const cleartext = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64UrlDecode(iv)
      },
      this.#internalState.encryptionKey,
      base64UrlDecode(ciphertext)
    )
    const serializedState = new TextDecoder().decode(cleartext)
    return this.config.stateParser(serializedState)
  }

  private async encryptState(state: StateType) {
    if (this.#internalState.state !== 'loaded') {
      throw new Error('LocalSecretStateSync is not ready')
    }
    const serializedState = this.config.stateSerializer(state)
    const iv = window.crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      this.#internalState.encryptionKey,
      new TextEncoder().encode(serializedState)
    )
    return [
      base64UrlEncode(iv),
      base64UrlEncode(new Uint8Array(ciphertext))
    ].join('.')
  }
}
