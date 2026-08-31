import { createHmac } from 'node:crypto';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decode a base32 secret (as shown on the MFA setup page). */
function decodeBase32(secret: string): Buffer {
	const cleaned = secret.replace(/[\s=]+/g, '').toUpperCase();
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const ch of cleaned) {
		const idx = BASE32.indexOf(ch);
		if (idx === -1) continue;
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	return Buffer.from(out);
}

/**
 * RFC 6238 TOTP (SHA-1, 30s step, 6 digits) — matches github.com/pquerna/otp defaults.
 */
export function totpCode(secret: string, atMs = Date.now()): string {
	const key = decodeBase32(secret);
	const counter = Math.floor(atMs / 1000 / 30);
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(BigInt(counter));
	const hmac = createHmac('sha1', key).update(buf).digest();
	const offset = hmac[hmac.length - 1] & 0x0f;
	const bin =
		((hmac[offset] & 0x7f) << 24) |
		((hmac[offset + 1] & 0xff) << 16) |
		((hmac[offset + 2] & 0xff) << 8) |
		(hmac[offset + 3] & 0xff);
	return String(bin % 1_000_000).padStart(6, '0');
}
