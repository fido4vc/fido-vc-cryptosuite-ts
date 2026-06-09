import { createHash } from 'crypto';
import JCS from 'canonicalize';
import {
  PROOF_GENERATION_ERROR,
  PROOF_TRANSFORMATION_ERROR,
  PROOF_VERIFICATION_ERROR,
} from '../lib/errors';
import type { JsonDocument } from '../types';
import { verifyFidoSignature } from './verify-signature-jwk';
import { defaultResolver, VerificationMethodResolver } from '../lib/resolver';

const SUITE_NAME = 'fido4vc-jcs-2026';
const PROOF_TYPE = 'DataIntegrityProof';

export function transform(doc: JsonDocument, options: JsonDocument): Buffer {
  if (options['type'] !== PROOF_TYPE || options['cryptosuite'] !== SUITE_NAME) {
    throw PROOF_TRANSFORMATION_ERROR(
      `options.type must be "${PROOF_TYPE}" and options.cryptosuite must be "${SUITE_NAME}"`
    );
  }
  return Buffer.from(JCS(doc)!);
}

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

export function hash(transformedDoc: Buffer, proofConfig: Buffer): Buffer {
  const proofConfigHash = createHash('sha256').update(proofConfig).digest();
  const documentHash = createHash('sha256').update(transformedDoc).digest();
  return Buffer.concat([proofConfigHash, documentHash]);
}

export async function proofVerification(
  hashData: Buffer,
  authenticatorData: Buffer,
  signature: Buffer,
  clientDataJSON: Buffer,
  options: JsonDocument,
  resolver?: VerificationMethodResolver
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

  const verificationMethod = options['verificationMethod'];
  if (typeof verificationMethod !== 'string') {
    throw PROOF_VERIFICATION_ERROR('proof.verificationMethod must be a string');
  }
  const publicKey = await (resolver ?? defaultResolver).resolveVerificationMethod(
    verificationMethod
  );

  if (publicKey.kty !== 'EC') {
    throw PROOF_VERIFICATION_ERROR('verificationMethod must resolve to an EC public key');
  }

  if (clientData['challenge'] !== hashData.toString('base64url')) {
    throw PROOF_VERIFICATION_ERROR('clientDataJSON.challenge does not match hashData');
  }

  const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
  const signedBytes = Buffer.concat([authenticatorData, clientDataHash]);

  return verifyFidoSignature({
    keyData: publicKey,
    signature: new Uint8Array(signature),
    data: new Uint8Array(signedBytes),
  });
}
