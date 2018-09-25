roughtime
=========

This module implements a [Roughtime][] client for [Node.js][] v6.x and up.

### Roughtime?

Roughtime is a project that aims to provide secure time synchronisation.

With [NTP][], a third party can intercept and modify replies from the server.
The reply you get is not necessarily and certainly not provably what the server
sent.

Roughtime replies cannot be forged: they are cryptographically signed using
[Ed25519][]. Clients can also create audit trails to help weed out misbehaving
servers (another common problem with NTP.)

See the [Roughtime][] homepage for more information.

### Concepts

* Midpoint is the server's idea of "now" relative to the [UNIX epoch][],
  expressed in microseconds.

* Radius is the server's uncertainty about the midpoint, also expressed
  in microseconds.

The server asserts that the true time is within `midpoint - radius/2` and
`midpoint + radius/2`.

Return-trip network latency is not accounted for. Expect that to be on the
order of several milliseconds.

Leap seconds are smeared out over the course of a day.

### Usage

Good ol' callback-style:

```js
const roughtime = require('roughtime')

roughtime('roughtime.cloudflare.com', (err, result) => {
	if (err) throw err
	const {midpoint, radius} = result
	console.log(midpoint, radius) // ex. "1537907399109000 1000000"
})
```

With promises:

```js
const {promise: roughtime} = require('roughtime')

roughtime('roughtime.cloudflare.com').then(result => {
	const {midpoint, radius} = result
	console.log(midpoint, radius) // ex. "1537907399109000 1000000"
})
```

Or with async/await:

```js
const {promise: roughtime} = require('roughtime')

async function f() {
	const {midpoint, radius} = await roughtime('roughtime.cloudflare.com')
	console.log(midpoint, radius) // ex. "1537907399109000 1000000"
}

f() // no top-level await yet in Node.js
```

`roughtime` currently knows about two public servers:

1. `roughtime.cloudflare.com`
2. `roughtime.sandbox.google.com`

To query other servers, provide the host name and optionally the port number,
and include the server's public key as a [Buffer][] or [Uint8Array][]:

```js
const roughtime = require('roughtime')

const pubkey = Uint8Array.from([0,0,0,0,/*...*/]) // must be 32 bytes

const options = {
	host: 'roughtime.example.com',
	port: 1337, // default is 2002
	pubkey: pubkey,
}

roughtime(options, (err, result) => {
	// ...
})
```

If you want to plug in your own nonce or UDP socket, you can: the options are
called `.nonce` and `.socket` respectively. The nonce must be a 64 byte
[Buffer][] or [Uint8Array][]:

```js
const roughtime = require('roughtime')
const {randomBytes} = require('crypto')

const host = 'roughtime.cloudflare.com'
const nonce = randomBytes(64)
const options = {host, nonce}

roughtime(options, (err, result) => {
	// ...
})
```

### Known bugs

* Auditing is not implemented. The ecosystem isn't large enough yet to make
  it practical.

* Merkle tree verification has only been lightly tested. I have yet to see
  a server in the wild return a reply that contains one.

[Buffer]: https://nodejs.org/docs/latest/api/buffer.html
[Ed25519]: https://ed25519.cr.yp.to/
[NTP]: http://www.ntp.org/
[Node.js]: https://nodejs.org/
[Roughtime]: https://roughtime.googlesource.com/roughtime/
[UNIX epoch]: https://en.wikipedia.org/wiki/Unix_time
[Uint8Array]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
