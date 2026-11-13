// Node's `crypto` as far as the bundled wallets use it (HERE Wallet: randomBytes for a nonce), from the browser's own
// cryptographically secure generator.
import { Buffer } from "buffer";

export function randomBytes(size) {
  const bytes = new Uint8Array(size);
  globalThis.crypto.getRandomValues(bytes);
  return Buffer.from(bytes);
}

export default { randomBytes };
