<h1 align="center">🔒♊️ <code>local-state-sync</code></h1>

<div align="center">

[![NPM](https://img.shields.io/npm/v/local-state-sync?color=red)](https://www.npmjs.com/package/local-state-sync)
[![MIT License](https://img.shields.io/github/license/47ng/local-state-sync.svg?color=blue)](https://github.com/47ng/local-state-sync/blob/next/LICENSE)
[![CI/CD](https://github.com/47ng/local-state-sync/workflows/CI%2FCD/badge.svg?branch=next)](https://github.com/47ng/local-state-sync/actions)
[![Coverage Status](https://coveralls.io/repos/github/47ng/local-state-sync/badge.svg?branch=next)](https://coveralls.io/github/47ng/local-state-sync?branch=next)

</div>

<p align="center">
  Persist & sync encrypted app state between browser tabs and pages
</p>

## Installation

```shell
$ yarn add local-state-sync
# or
$ npm i local-state-sync
```

## Usage

1. Generate an encryption key (32 bytes, base64url encoded):

```shell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

2. Create a LocalStateSync object

```ts
import { LocalStateSync } from 'local-state-sync'

const localStateSync = new LocalStateSync({
  // Required parameters
  encryptionKey: '...',
  onStateUpdated: state => console.dir(state)
})

await localStateSync.setState({
  name: 'Alice',
  age: 30
})
```

The `onStateUpdated` callback will be called when another tab or
window has called `setState`, or on load when reading an existing
persisted state.

## Parsing & Serializing

By default, `JSON.stringify` is used to convert your state to a string
before encryption, and `JSON.parse` to hydrate it after decryption.

For complex states, it's recommended to use a custom parser, like
[zod](https://github.com/colinhacks/zod).

```ts
import { z } from 'zod'

const stateParser = z.object({
  name: z.string(),
  age: z.number()
})

new LocalStateSync({
  // ...
  parseState: serializedState => stateParser.parse(JSON.parse(serializedState))
})
```

You can also provide a custom serializer:

```ts
new LocalStateSync<number>({
  // ...
  parseState: parseInt,
  serializeState: state => state.toFixed()
})
```

## TypeScript

The type of state is inferred from the first argument of the function you pass
to `onStateUpdated`.

You can also specify the state type explicitly:

```ts
type MyState = {
  name: string
  age: number
}

new LocalStateSync<MyState>({
  // ...
  onStateUpdated: console.dir
})
```

## Examples

### React

```tsx
import { LocalStateSync } from 'local-state-sync'
import React from 'react'

export const MySyncedComponent = () => {
  const [state, setState] = React.useState('')
  const [localStateSync] = React.useState(
    () =>
      new LocalStateSync<string>({
        encryptionKey: '...',
        onStateUpdated: state => setState(state)
      })
  )
  return (
    <input
      value={state}
      onChange={e => {
        setState(e.target.event)
        localStateSync.setState(e.target.event)
      }}
    />
  )
}
```

🙏 _Contributions welcome for other frameworks_

## Threat modelling

This should be secure against other scripts running on the same origin,
as long as you don't store the encryption key itself in accessible storage.

It will **not** be secure against an attacker that inspects the source
code of the page (eg: browser extensions) to find the key and can run
arbitrary scripts on your origin to decrypt the stored state.

## Cryptography

State is encrypted using AES-GCM with a 256 bit key.

The IV and ciphertext are base64url encoded, and joined together using a dot `.` character:

```
5otu-QPdwu3_fL9Y.tYtssqv_YASLeW65aLqrd66l4RECKJtr-R20n5odkA
[ iv (12 bytes)].[ ciphertext                             ]
```

The storage key is the SHA-256 hash of the encryption key in base64url.
