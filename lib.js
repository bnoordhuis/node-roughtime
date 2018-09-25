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

const {crypto_sign_open} = require('tweetnacl').lowlevel
const {createHash, randomBytes} = require('crypto')
const {createSocket} = require('dgram')

const CERT = 0x54524543
const DELE = 0x454c4544
const INDX = 0x58444e49
const MAXT = 0x5458414d
const MIDP = 0x5044494d
const MINT = 0x544e494d
const NONC = 0x434e4f4e
const PAD = 0xff444150
const PATH = 0x48544150
const PUBK = 0x4b425550
const RADI = 0x49444152
const ROOT = 0x544f4f52
const SIG = 0x00474953
const SREP = 0x50455253

const knownHosts = {
	'roughtime.cloudflare.com:2002': unbase64('gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo='),
	'roughtime.sandbox.google.com:2002': unbase64('etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ='),
}
Object.setPrototypeOf(knownHosts, null)

const certificateContext = bytes('RoughTime v1 delegation signature--\x00')
const signedResponseContext = bytes('RoughTime v1 response signature\x00')

const zero = Uint8Array.from([0])
const one = Uint8Array.from([1])

const scratch0 = new Uint8Array(2048)
const scratch1 = new Uint8Array(2048)

// |b| is a Buffer instead of a Uint8Array because dgram.Socket#send() in
// older Node.js versions only accepts Buffers.
const b = Buffer.alloc ? Buffer.alloc(1024) : new Buffer(1024)

b[0] = 2 // 2 tags; NONC and PAD
b[4] = 64 // 2nd tag (PAD) starts 64 bytes after header
b[8] = 78; b[9] = 79; b[10] = 78; b[11] = 67 // tag 'NONC'
b[12] = 80; b[13] = 65; b[14] = 68; b[15] = 255 // tag 'PAD\xff'

function roughtime(options, cb) {
	if (typeof cb !== 'function') {
		throw new TypeError('callback required')
	}

	if (typeof options === 'string') {
		options = {host: options}
	}

	let {host, nonce, port, pubkey, socket} = options
	port = port>>>0 || 2002
	pubkey = pubkey || knownHosts[host + ':' + port]

	if (nonce != null && nonce.length !== 64) {
		throw new TypeError('nonce must be 64 bytes')
	}

	if (pubkey == null) {
		throw new TypeError('server pubkey required')
	}

	if (pubkey.length !== 32) {
		throw new TypeError('pubkey must be 32 bytes')
	}

	if (nonce) {
		next(null, nonce)
	} else {
		randomBytes(64, next)
	}

	function next(err, nonce) {
		if (err) {
			return cb(err)
		}

		for (let i = 0; i < 64; i++) {
			b[i+16] = nonce[i]
		}

		const ownsocket = (socket == null)
		if (ownsocket) {
			const {createSocket} = module.exports
			socket = createSocket('udp4')
		}

		socket.send(b, port, host)

		socket.once('message', b => {
			if (ownsocket) {
				socket.close()
			}

			const [midpoint, radius, err] = parse(pubkey, nonce, b)
			cb(err, {midpoint, radius})
		})
	}
}

roughtime.promise = function(options) {
	return new Promise((resolve, reject) => {
		roughtime(options, (err, result) => {
			if (err) {
				reject(err)
			} else {
				resolve(result)
			}
		})
	})
}

function parse(pubkey, nonce, b) {
	let CERT_tagstart = -1
	let CERT_tagend = -1
	let INDX_tagstart = -1
	let INDX_tagend = -1
	let PATH_tagstart = -1
	let PATH_tagend = -1
	let SIG_tagstart = -1
	let SIG_tagend = -1
	let SREP_tagstart = -1
	let SREP_tagend = -1
	let CERT_DELE_tagstart = -1
	let CERT_DELE_tagend = -1
	let CERT_SIG_tagstart = -1
	let CERT_SIG_tagend = -1
	let CERT_DELE_MAXT_tagstart = -1
	let CERT_DELE_MAXT_tagend = -1
	let CERT_DELE_MINT_tagstart = -1
	let CERT_DELE_MINT_tagend = -1
	let CERT_DELE_PUBK_tagstart = -1
	let CERT_DELE_PUBK_tagend = -1
	let SREP_MIDP_tagstart = -1
	let SREP_MIDP_tagend = -1
	let SREP_RADI_tagstart = -1
	let SREP_RADI_tagend = -1
	let SREP_ROOT_tagstart = -1
	let SREP_ROOT_tagend = -1

	let s = 0
	let i = 0
	let n = b.length

	if (n%4 > 0) {
		return reject(b, 'short message')
	}

done:
	for (;;) {
		if (i+4 > n) {
			return reject(b, 'short message')
		}

		const ntags = uint32(b, i)
		i += 4

		if (ntags === 0) {
			return reject(b, 'no tags') // not technically illegal but...
		}

		const firstoffset = i
		i += 4*(ntags-1)
		const lastoffset = i

		const firsttag = i
		i += 4*ntags
		const lasttag = i

		const firstdatabyte = i

		if (i > n) {
			return reject(b, 'short message')
		}

		for (let last = -1, j = firstoffset; j < lastoffset; j += 4) {
			const offset = uint32(b, j)

			if (offset < last) {
				return reject(b, 'illegal offset (order)')
			}
			last = offset

			if (offset%4 > 0) {
				return reject(b, 'illegal offset (alignment)')
			}

			if (offset+firstdatabyte > n) {
				return reject(b, 'illegal offset (range)')
			}
		}

		let tagstart = firstdatabyte
		let tagend = -1

		for (let j = firsttag; j < lasttag; j += 4, tagstart = tagend) {
			tagend = n

			if (j+4 < lasttag) {
				tagend = firstdatabyte + uint32(b, j - firsttag + firstoffset)
			}

			const tag = uint32(b, j)

			switch (s) {
				case 0: // toplevel
					switch (tag) {
					case CERT:
						CERT_tagstart = tagstart
						CERT_tagend = tagend
						break
					case INDX:
						INDX_tagstart = tagstart
						INDX_tagend = tagend
						break
					case PATH:
						PATH_tagstart = tagstart
						PATH_tagend = tagend
						break
					case SIG:
						SIG_tagstart = tagstart
						SIG_tagend = tagend
						break
					case SREP:
						SREP_tagstart = tagstart
						SREP_tagend = tagend
						break
					}
					break

				case 1: // CERT
					switch (tag) {
					case DELE:
						CERT_DELE_tagstart = tagstart
						CERT_DELE_tagend = tagend
						break
					case SIG:
						CERT_SIG_tagstart = tagstart
						CERT_SIG_tagend = tagend
						break
					}
					break

				case 2: // CERT_DELE
					switch (tag) {
					case MAXT:
						CERT_DELE_MAXT_tagstart = tagstart
						CERT_DELE_MAXT_tagend = tagend
						break
					case MINT:
						CERT_DELE_MINT_tagstart = tagstart
						CERT_DELE_MINT_tagend = tagend
						break
					case PUBK:
						CERT_DELE_PUBK_tagstart = tagstart
						CERT_DELE_PUBK_tagend = tagend
						break
					}
					break

				case 3: // SREP
					switch (tag) {
					case MIDP:
						SREP_MIDP_tagstart = tagstart
						SREP_MIDP_tagend = tagend
						break
					case RADI:
						SREP_RADI_tagstart = tagstart
						SREP_RADI_tagend = tagend
						break
					case ROOT:
						SREP_ROOT_tagstart = tagstart
						SREP_ROOT_tagend = tagend
						break
					}
					break
			}
		}

		switch (s) {
		case 0: // toplevel
			if (CERT_tagstart < 0) {
				return reject(b, 'no CERT tag')
			}

			if (INDX_tagstart < 0) {
				return reject(b, 'no INDX tag')
			}

			if (INDX_tagend-INDX_tagstart !== 4) {
				return reject(b, 'bad INDX tag')
			}

			if (PATH_tagstart < 0) {
				return reject(b, 'no PATH tag')
			}

			if ((PATH_tagend-PATH_tagstart)%64 !== 0) {
				return reject(b, 'bad PATH tag')
			}

			if (SIG_tagstart < 0) {
				return reject(b, 'no SIG tag')
			}

			if (SIG_tagend-SIG_tagstart !== 64) {
				return reject(b, 'bad SIG tag')
			}

			if (SREP_tagstart < 0) {
				return reject(b, 'no SREP tag')
			}

			i = CERT_tagstart
			n = CERT_tagend
			s++ // CERT
			break

		case 1: // CERT
			if (CERT_DELE_tagstart < 0) {
				return reject(b, 'no CERT.DELE tag')
			}

			if (CERT_SIG_tagstart < 0) {
				return reject(b, 'no CERT.SIG tag')
			}

			if (CERT_SIG_tagend-CERT_SIG_tagstart !== 64) {
				return reject(b, 'bad CERT.SIG tag')
			}

			i = CERT_DELE_tagstart
			n = CERT_DELE_tagend
			s++ // CERT_DELE
			break

		case 2: // CERT_DELE
			if (CERT_DELE_MAXT_tagstart < 0) {
				return reject(b, 'no CERT.DELE.MAXT tag')
			}

			if (CERT_DELE_MAXT_tagend-CERT_DELE_MAXT_tagstart !== 8) {
				return reject(b, 'bad CERT.DELE.MAXT tag')
			}

			if (CERT_DELE_MINT_tagstart < 0) {
				return reject(b, 'no CERT.DELE.MINT tag')
			}

			if (CERT_DELE_MINT_tagend-CERT_DELE_MINT_tagstart !== 8) {
				return reject(b, 'bad CERT.DELE.MAXT tag')
			}

			if (CERT_DELE_PUBK_tagstart < 0) {
				return reject(b, 'no CERT.DELE.PUBK tag')
			}

			if (CERT_DELE_PUBK_tagend-CERT_DELE_PUBK_tagstart !== 32) {
				return reject(b, 'bad CERT.DELE.PUBK')
			}

			i = SREP_tagstart
			n = SREP_tagend
			s++ // SREP
			break

		case 3: // SREP
			if (SREP_MIDP_tagstart < 0) {
				return reject(b, 'no SREP.MIDP tag')
			}

			if (SREP_MIDP_tagend-SREP_MIDP_tagstart !== 8) {
				return reject(b, 'bad SREP.MIDP tag')
			}

			if (SREP_RADI_tagstart < 0) {
				return reject(b, 'no SREP.RADI tag')
			}

			if (SREP_RADI_tagend-SREP_RADI_tagstart !== 4) {
				return reject(b, 'bad SREP.RADI tag')
			}

			if (SREP_ROOT_tagstart < 0) {
				return reject(b, 'no SREP.ROOT tag')
			}

			if (SREP_ROOT_tagend-SREP_ROOT_tagstart !== 64) {
				return reject(b, 'bad SREP.ROOT tag')
			}

			break done
		}
	}

	{
		const sig = b.subarray(CERT_SIG_tagstart, CERT_SIG_tagend)

		if (!verify(sig, certificateContext, b, CERT_DELE_tagstart, CERT_DELE_tagend, pubkey)) {
			return reject(b, 'CERT.DELE does not verify')
		}
	}

	{
		const sig = b.subarray(SIG_tagstart, SIG_tagend)
		const key = b.subarray(CERT_DELE_PUBK_tagstart, CERT_DELE_PUBK_tagend)

		if (!verify(sig, signedResponseContext, b, SREP_tagstart, SREP_tagend, key)) {
			return reject(b, 'SREP does not verify')
		}
	}

	let h = createHash('sha512').
		update(zero).
		update(nonce).
		digest()

	const pathlen = PATH_tagend - PATH_tagstart
	if (pathlen > 0) {
		let index = uint32(b, INDX_tagstart)

		for (let j = 0; j < pathlen; j += 64) {
			let l = b.subarray(PATH_tagstart+j, PATH_tagstart+j+64)
			let r = h

			if (index&1 === 0) {
				[l, r] = [r, l]
			}

			h = createHash('sha512').
				update(one).
				update(l).
				update(r).
				digest()

			index >>>= 1
		}
	}

	{
		let i = 0

		for (let j = 0; j < 64; j++) {
			i ^= h[j]
			i ^= b[j+SREP_ROOT_tagstart]
		}

		if (i !== 0) {
			return reject(b, 'ROOT does not verify')
		}
	}

	const midpoint = uint64(b, SREP_MIDP_tagstart)
	const radius = uint32(b, SREP_RADI_tagstart)

	return [midpoint, radius, null]
}

function reject(b, s) {
	const err = new Error(s)
	err.reply = b
	return [0, 0, err]
}

function verify(sig, prefix, b, start, end, pubkey) {
	const prefixlen = prefix.length
	const msglen = end-start
	const len = 64 + prefixlen + msglen

	if (len > scratch0.length) {
		return false
	}

	let k = 0
	for (let i = 0; i < 64; i++, k++) {
		scratch0[k] = sig[i]
	}

	for (let i = 0; i < prefixlen; i++, k++) {
		scratch0[k] = prefix[i]
	}

	for (let i = start; i < end; i++, k++) {
		scratch0[k] = b[i]
	}

	return 0 <= crypto_sign_open(scratch1, scratch0, len, pubkey)
}

function unbase64(s) {
	return Uint8Array.from(Buffer.from(s, 'base64'))
}

function bytes(s) {
	return Uint8Array.from(s.split('').map(c => c.charCodeAt(0)))
}

function uint32(b, i) {
	return b[i+0] + 256*b[i+1] + 65536*b[i+2] + 16777216*b[i+3]
}

function uint64(b, i) {
	const lo = uint32(b, i+0)
	const hi = uint32(b, i+4)
	if (hi < 2097153) {
		return 4294967296*hi + lo
	}
	if (typeof BigInt === 'function') {
		return BigInt(4294967296) * BigInt(hi) + BigInt(lo)
	}
	return '4294967296*' + hi + '+' + lo
}

module.exports = {createSocket, knownHosts, parse, roughtime, unbase64}
