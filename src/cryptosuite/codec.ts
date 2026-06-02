import { decode as cborDecode, encode as cborEncode } from 'cbor-x';
import { PROOF_VERIFICATION_ERROR } from '../lib/errors';
import type { WebAuthnAssertion } from '../types';

export function encodeProofValue(assertion: WebAuthnAssertion): string {
  const { authenticatorData, signature, clientDataJSON } = assertion;
  const cbor = cborEncode([
    new Uint8Array(authenticatorData),
    new Uint8Array(signature),
    new Uint8Array(clientDataJSON),
  ]);
  return 'u' + Buffer.from(cbor).toString('base64url');
}

export function decodeProofValue(proofBytes: Buffer): [Buffer, Buffer, Buffer] {
  let decoded: unknown;
  try {
    decoded = cborDecode(proofBytes);
  } catch (err) {
    throw PROOF_VERIFICATION_ERROR(
      `proofValue CBOR decode failed: ${(err as Error).message ?? err}`
    );
  }
  if (
    !Array.isArray(decoded) ||
    decoded.length !== 3 ||
    !decoded.every((v) => v instanceof Uint8Array)
  ) {
    throw PROOF_VERIFICATION_ERROR(
      'proofValue CBOR must decode to a 3-element array of byte strings'
    );
  }
  return decoded.map((v) => Buffer.from(v as Uint8Array)) as [Buffer, Buffer, Buffer];
}
