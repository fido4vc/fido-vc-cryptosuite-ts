import { createHash } from 'crypto';
import { decode as cborDecode, encode as cborEncode } from 'cbor-x';
import JCS from 'canonicalize';
import { defaultResolver } from '../../lib/resolver';
import { verifyFidoSignature } from './verify-signature-jwk';
import {
  PROOF_GENERATION_ERROR,
  PROOF_TRANSFORMATION_ERROR,
  PROOF_VERIFICATION_ERROR,
} from '../../lib/errors';

import type {
  Cryptosuite,
  JsonDocument,
  Proof,
  VerificationResult,
  WebAuthnAssertion,
} from '../../types';

const SUITE_NAME = 'fido4vc-jcs-2026';
const PROOF_TYPE = 'DataIntegrityProof';
const PROOF_PURPOSE = 'authentication';

/**
 * Produces the JCS-canonical UTF-8 byte sequence of the unsecured document.
 * Raises PROOF_TRANSFORMATION_ERROR if the options do not match this suite.
 */
export function transform(doc: JsonDocument, options: JsonDocument): Buffer {
  if (options['type'] !== PROOF_TYPE || options['cryptosuite'] !== SUITE_NAME) {
    throw PROOF_TRANSFORMATION_ERROR(
      `options.type must be "${PROOF_TYPE}" and options.cryptosuite must be "${SUITE_NAME}"`
    );
  }
  return Buffer.from(JCS(doc)!);
}

/**
 * Produces the JCS-canonical UTF-8 byte sequence of the proof configuration.
 * Clones `options`, removes `proofValue`, injects `@context` from the document,
 * validates required fields, and canonicalises.
 */
export function proofConfiguration(options: JsonDocument, doc: JsonDocument): Buffer {
  const proofConfig: JsonDocument = { ...options };

  if (proofConfig['type'] !== PROOF_TYPE || proofConfig['cryptosuite'] !== SUITE_NAME) {
    throw PROOF_GENERATION_ERROR(
      `proofConfig.type must be "${PROOF_TYPE}" and proofConfig.cryptosuite must be "${SUITE_NAME}"`
    );
  }

  if (proofConfig['created'] !== undefined) {
    const created = proofConfig['created'];
    if (typeof created !== 'string' || isNaN(Date.parse(created))) {
      throw PROOF_GENERATION_ERROR('proofConfig.created is not a valid XML Schema dateTime');
    }
  }

  delete proofConfig['proofValue'];

  proofConfig['@context'] = doc['@context'];

  return Buffer.from(JCS(proofConfig)!);
}

/**
 * Produces the 64-byte hashData:
 *   SHA-256(canonicalProofConfig) ‖ SHA-256(transformedDocument)
 */
export function hash(transformedDoc: Buffer, proofConfig: Buffer): Buffer {
  const proofConfigHash = createHash('sha256').update(proofConfig).digest();
  const documentHash = createHash('sha256').update(transformedDoc).digest();
  return Buffer.concat([proofConfigHash, documentHash]);
}

/**
 * §3.2/§3.7 phase 1 — Computes the 64-byte hashData that becomes the WebAuthn challenge.
 * Pass the returned Buffer directly to navigator.credentials.get({ challenge: hashData }).
 */
export function startCreateProof(options: JsonDocument, unsecuredDocument: JsonDocument): Buffer {
  const transformedBytes = transform(unsecuredDocument, options);
  const proofConfigBytes = proofConfiguration(options, unsecuredDocument);
  return hash(transformedBytes, proofConfigBytes);
}

/**
 * §3.2/§3.7 phase 2 — Packages the authenticator's assertion response into a secured document.
 * `assertion` maps to the fields of AuthenticatorAssertionResponse from the WebAuthn API.
 */
export function finishCreateProof(assertion: WebAuthnAssertion, options: JsonDocument): Proof {
  const { authenticatorData, signature, clientDataJSON } = assertion;
  const cbor = cborEncode([
    new Uint8Array(authenticatorData),
    new Uint8Array(signature),
    new Uint8Array(clientDataJSON),
  ]);
  const proofValue = 'u' + Buffer.from(cbor).toString('base64url');
  return { ...options, proofValue } as Proof;
}

/**
 * Verifies the WebAuthn assertion against the derived hashData.
 * Returns true if the ECDSA signature is valid and all binding checks pass.
 */
async function proofVerification(
  hashData: Buffer,
  authenticatorData: Buffer,
  signature: Buffer,
  clientDataJSON: Buffer,
  options: JsonDocument
): Promise<boolean> {
  let clientData: JsonDocument;
  try {
    clientData = JSON.parse(clientDataJSON.toString('utf8')) as JsonDocument;
  } catch {
    throw PROOF_VERIFICATION_ERROR('clientDataJSON is not valid UTF-8 JSON');
  }

  if (clientData['type'] !== 'webauthn.get') {
    throw PROOF_VERIFICATION_ERROR(
      `clientDataJSON.type must be "webauthn.get", got "${clientData['type']}"`
    );
  }

  if (clientData['challenge'] !== hashData.toString('base64url')) {
    throw PROOF_VERIFICATION_ERROR('clientDataJSON.challenge does not match hashData');
  }

  const verificationMethod = options['verificationMethod'];
  if (typeof verificationMethod !== 'string') {
    throw PROOF_VERIFICATION_ERROR('proof.verificationMethod must be a string');
  }
  const publicKey = await defaultResolver.resolveVerificationMethod(verificationMethod);

  // Validate key type (spec §2.1)
  if (publicKey.kty !== 'EC') {
    throw PROOF_VERIFICATION_ERROR('verificationMethod must resolve to an EC public key');
  }

  const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
  const signedBytes = Buffer.concat([authenticatorData, clientDataHash]);

  return verifyFidoSignature({
    keyData: publicKey,
    signature: new Uint8Array(signature),
    data: new Uint8Array(signedBytes),
  });
}

function decodeCborProofValue(proofBytes: Buffer): [Buffer, Buffer, Buffer] {
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

/**
 * Verifies a secured data document and returns a VerificationResult.
 * All errors are caught and returned as { verified: false, error }.
 */
export async function verifyProof(securedDoc: JsonDocument): Promise<VerificationResult> {
  try {
    const { proof: rawProofField, ...unsecuredDocument } = securedDoc;

    const rawProof = Array.isArray(rawProofField) ? rawProofField[0] : rawProofField;
    if (!rawProof || typeof rawProof !== 'object') {
      throw PROOF_VERIFICATION_ERROR('securedDocument.proof is missing or not an object');
    }
    const proof = rawProof as JsonDocument;

    if (proof['proofPurpose'] !== PROOF_PURPOSE) {
      throw PROOF_VERIFICATION_ERROR(`proof.proofPurpose must be ${PROOF_PURPOSE}`);
    }

    const proofValue = proof['proofValue'];
    if (typeof proofValue !== 'string' || !proofValue.startsWith('u')) {
      throw PROOF_VERIFICATION_ERROR(
        'proof.proofValue must be a multibase string starting with "u"'
      );
    }
    const proofBytes = Buffer.from(proofValue.slice(1), 'base64url');
    const [authenticatorData, signature, clientDataJSON] = decodeCborProofValue(proofBytes);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { proofValue: _pv, ...options } = proof;
    const proofConfigBytes = proofConfiguration(options, unsecuredDocument);
    const transformedBytes = transform(unsecuredDocument, options);
    const hashData = hash(transformedBytes, proofConfigBytes);
    const verified = await proofVerification(
      hashData,
      authenticatorData,
      signature,
      clientDataJSON,
      options
    );
    return {
      verified,
      verifiedDocument: verified ? unsecuredDocument : undefined,
    };
  } catch (error) {
    return { verified: false, error };
  }
}

export async function createProof(
  _unsecuredDocument: JsonDocument,
  _options: JsonDocument
): Promise<Proof> {
  throw new Error('Proof creation is not implemented in this suite');
}

export const Fido4vcCryptosuite = {
  name: SUITE_NAME,
  startCreateProof,
  finishCreateProof,
  verifyProof,
  createProof, // throws if called
} satisfies Cryptosuite;
