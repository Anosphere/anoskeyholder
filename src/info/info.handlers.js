import { env } from '../config/env.js';
import { receivingPublicKey } from '../crypto/keyholder-keys.js';
import { toHex } from '../util/ids.js';

/**
 * POST /get-keyholder-public-key (spec 5.1). Body {} (not read). Answers
 * this keyholder's number and the raw public halves of its receiving key
 * pair in hex (32 and 1568 bytes), which the phone encrypts every share to.
 */
export function getKeyholderPublicKey(req, res) {
  res.status(200).json({
    keyholderId: env.keyholderId,
    receivingKey: {
      x25519: toHex(receivingPublicKey.x25519),
      mlkem: toHex(receivingPublicKey.mlkem),
    },
  });
}
