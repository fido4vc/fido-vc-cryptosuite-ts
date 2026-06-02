// Based on @simplewebauthn/server/helpers/unwrapEC2Signature.ts.

import { AsnParser } from '@peculiar/asn1-schema';
import { ECDSASigValue } from '@peculiar/asn1-ecc';

export type CrvType = 'P-256' | 'P-384' | 'P-521';

/**
 * In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
 *
 * See https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 */
export function unwrapEC2Signature(signature: Uint8Array<ArrayBuffer>, crv: CrvType): Uint8Array<ArrayBuffer> {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  const rBytes = new Uint8Array(parsedSignature.r);
  const sBytes = new Uint8Array(parsedSignature.s);

  const componentLength = getSignatureComponentLength(crv);
  const rNormalizedBytes = toNormalizedBytes(rBytes, componentLength);
  const sNormalizedBytes = toNormalizedBytes(sBytes, componentLength);

  const finalSignature = new Uint8Array(rNormalizedBytes.length + sNormalizedBytes.length);
  finalSignature.set(rNormalizedBytes, 0);
  finalSignature.set(sNormalizedBytes, rNormalizedBytes.length);

  return finalSignature;
}

/**
 * The SubtleCrypto Web Crypto API expects ECDSA signatures with `r` and `s` values to be encoded
 * to a specific length depending on the order of the curve. This function returns the expected
 * byte-length for each of the `r` and `s` signature components.
 *
 * See <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function getSignatureComponentLength(crv: CrvType): number {
  switch (crv) {
    case 'P-256':
      return 32;
    case 'P-384':
      return 48;
    case 'P-521':
      return 66;
    default:
      throw new Error(`Unexpected COSE crv value of ${crv} (EC2)`);
  }
}

/**
 * Converts the ASN.1 integer representation to bytes of a specific length `n`.
 *
 * DER encodes integers as big-endian byte arrays, with as small as possible representation and
 * requires a leading `0` byte to disambiguate between negative and positive numbers. This means
 * that `r` and `s` can potentially not be the expected byte-length that is needed by the
 * SubtleCrypto Web Crypto API: if there are leading `0`s it can be shorter than expected, and if
 * it has a leading `1` bit, it can be one byte longer.
 *
 * See <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
 * See <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function toNormalizedBytes(bytes: Uint8Array<ArrayBuffer>, componentLength: number): Uint8Array<ArrayBuffer> {
  let normalizedBytes: Uint8Array<ArrayBuffer>;

  if (bytes.length < componentLength) {
    // In case the bytes are shorter than expected, we need to pad it with leading `0`s.
    normalizedBytes = new Uint8Array(componentLength);
    normalizedBytes.set(bytes, componentLength - bytes.length);
  } else if (bytes.length === componentLength) {
    normalizedBytes = bytes;
  } else if (bytes.length === componentLength + 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0x80) {
    // The bytes contain a leading `0` to encode that the integer is positive. This leading `0`
    // needs to be removed for compatibility with the SubtleCrypto Web Crypto API.
    normalizedBytes = bytes.subarray(1);
  } else {
    throw new Error(
      `Invalid signature component length ${bytes.length}, expected ${componentLength}`
    );
  }

  return normalizedBytes;
}
