// Copyright (c) 2018, Ben Noordhuis <info@bnoordhuis.nl>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

'use strict'

const {ifError, strictEqual, throws} = require('assert')
const {EventEmitter} = require('events')
const dgram = require('dgram')

const roughtime = require('./')
const lib = require('./lib')

const {knownHosts, parse, unbase64} = lib

const good = [
	{
		host: 'roughtime.sandbox.google.com',
		port: 2002,
		nonce: unbase64('R6TcpZE050RT1hKy+6/ylQi0KZLeeuJYpaVCJSotCpnCVMrJFXcdI9lOrFfEPB0EfyXZhElIBEGdtYHCTJccUg=='),
		reply: unbase64('BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWP3RfJdwvvUXVq2eSPBALJLjzGtSmjvp4okJcfOBy0Yd0MaZd4l9N9FxCeT10UBhHmIw6jSiUp9ovHxwZ2sPrwsDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8ALb0W/bd2BQACpCWdwyGMb22WYsb6niX6lo3ktuBni5hQybT1OiqGiGAfB8lNDAdRj42v6V/KKRfrgYo7xvrCZHJNjwfpte98AgAAAEAAAABTSUcAREVMRZN5+EgOFeb0Xa7BiGFlBIW0F43xa2f40Zk1nhImmspM4Sns1h7VXHG/+9e47A/Hy8+P6z9OQWvLTGb9Dpm6oggDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR63nJwYksxXpxTvEcvO6blQBInMghgvtkUFbpJmitoGQDwHQy1dgUAANBSoRl3BQAAAAAA'),
		midpoint: 1537907480771885,
		radius: 1000000,
	},
	{
		host: 'roughtime.cloudflare.com',
		port: 2002,
		nonce: unbase64('QnOCgaenvI0Xm6iseW3bFjAyXZk1Zg5d9N5UkHZA01psFr5rxp0X0ye6YChSfGx9cBTkwE6GEK5zybMqYGp9IA=='),
		reply: unbase64('BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWMJLPn8Bg/JtA5KJsgFIEj+TCuG/ObLtq1hxK9AE0U8GRVmQS4CcKcIQIoMkLsyYsFyS88Ss/Ol/v7x+LxjtGAkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AiKk4+Ld2BQC8cb9UKjuEcYgUx2jCYyv7Dj8Mvjdmw0YCcdhhfrEOWynt2ZHaorZfmg/nrw4GirxAv+p3YHUn+/KNxj8uQD8NAgAAAEAAAABTSUcAREVMRW9c/czJdx96KE3mbpBVJLBDLIB8XEeAWUZpHCk5RKiTN6sRDprZVRO3OVx8ZXiqzU6H6NuahDjqyCmXaYKyCA0DAAAAIAAAACgAAABQVUJLTUlOVE1BWFQTCK+Zq7yqR3XuAJTchqrLEksjiphD7XF+vTxSXjL2B2BmHxC2dgUAYMb2Lcp2BQAAAAAA'),
		midpoint: 1537907399109000,
		radius: 1000000,
	},
]

process.setMaxListeners(Infinity)

strictEqual(roughtime, lib.roughtime)

{
	const host = 'example.com'
	const {abort} = process
	throws(() => roughtime(host), /callback required/)
	throws(() => roughtime(host, null), /callback required/)
	throws(() => roughtime(host, abort), /server pubkey required/)
	throws(() => roughtime({host, nonce: new Uint8Array()}, abort), /nonce must be 64 bytes/)
	throws(() => roughtime({host, pubkey: new Uint8Array()}, abort), /pubkey must be 32 bytes/)
}

good.forEach(t => {
	const pubkey = knownHosts[t.host + ':' + t.port]
	const [midpoint, radius, err] = parse(pubkey, t.nonce, t.reply)
	ifError(err)
	strictEqual(midpoint, t.midpoint)
	strictEqual(radius, t.radius)
})

{
	callback(0)

	function callback(i) {
		test('callback', i, promise)
	}

	function promise(i) {
		test('promise', i, i => callback(i + 1))
	}

	function test(what, i, next) {
		const t = good[i]

		if (!t) {
			return
		}

		let sendcalls = 0
		let closecalls = 0
		let cbcalls = 0

		process.on('exit', () => {
			strictEqual(sendcalls, 1)
			strictEqual(closecalls, 1)
		})

		const {createSocket} = lib
		lib.createSocket = type => {
			strictEqual(type, 'udp4')

			const socket = new class extends EventEmitter {
				send(b, port, host) {
					sendcalls++
					strictEqual(sendcalls, 1)
					strictEqual(closecalls, 0)
					strictEqual(cbcalls, 0)
					strictEqual(port, t.port)
					strictEqual(host, t.host)
					setImmediate(() => socket.emit('message', t.reply))
				}

				close() {
					closecalls++
					strictEqual(closecalls, 1)
					strictEqual(sendcalls, 1)
					strictEqual(cbcalls, 0)
					lib.createSocket = createSocket
				}
			}

			return socket
		}

		const cb = (err, {midpoint, radius}) => {
			cbcalls++
			strictEqual(sendcalls, 1)
			strictEqual(closecalls, 1)
			strictEqual(cbcalls, 1)
			ifError(err)
			strictEqual(midpoint, t.midpoint)
			strictEqual(radius, t.radius)
			next(i)
		}

		const {host, nonce} = t
		const options = {host, nonce}

		switch (what) {
		case 'callback':
			roughtime(options, cb)
			break

		case 'promise':
			const then = result => cb(null, result)
			const catcher = err => { throw err }
			roughtime.promise(options).then(then).catch(catcher)
			break
		}

		strictEqual(cbcalls, 0)
		process.once('exit', () => strictEqual(cbcalls, 1))
	}
}

good.forEach(t => {
	test('callback')
	test('promise')

	function test(what) {
		let len = 0
		next()

		function next() {
			let cbcalls = 0
			let sendcalls = 0

			const socket = new class extends EventEmitter {
				send(b, port, host) {
					sendcalls++
					strictEqual(sendcalls, 1)
					strictEqual(cbcalls, 0)
					strictEqual(port, t.port)
					strictEqual(host, t.host)
					const reply = t.reply.slice(0, len)
					setImmediate(() => socket.emit('message', reply))
				}
			}

			const cb = (err, {midpoint, radius}) => {
				cbcalls++
				strictEqual(cbcalls, 1)
				strictEqual(sendcalls, 1)

				if (len === t.reply.length) {
					ifError(err)
					strictEqual(midpoint, t.midpoint)
					strictEqual(radius, t.radius)
				} else {
					strictEqual(err instanceof Error, true)
					strictEqual(midpoint, 0)
					strictEqual(radius, 0)
					len++
					next()
				}
			}

			const {host, nonce, port} = t

			switch (what) {
			case 'callback':
				roughtime({host, nonce, port, socket}, cb)
				break

			case 'promise':
				roughtime.promise({host, nonce, port, socket}).
					then(result => cb(null, result)).
					catch(err => cb(err, {midpoint: 0, radius: 0}))
				break
			}

			strictEqual(cbcalls, 0)
			process.once('exit', () => strictEqual(cbcalls, 1))
		}
	}
})
