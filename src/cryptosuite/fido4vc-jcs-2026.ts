import { VerificationMethodResolver } from '../lib/resolver';
import { DataIntegrityError, PROOF_VERIFICATION_ERROR } from '../lib/errors';
import { transform, proofConfiguration, hash, proofVerification } from './algorithms';
import { decodeProofValue, encodeProofValue } from './codec';
import type { JsonDocument, Proof, VerificationResult, WebAuthnAssertion } from '../types';

const PROOF_PURPOSE = 'authentication';
export const SUITE_NAME = 'fido4vc-jcs-2026';

export async function verifyProof(
  securedDoc: JsonDocument,
  resolver?: VerificationMethodResolver
): Promise<VerificationResult> {
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
    const [authenticatorData, signature, clientDataJSON] = decodeProofValue(proofBytes);

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
      options,
      resolver
    );
    return {
      verified,
      verifiedDocument: verified ? unsecuredDocument : undefined,
    };
  } catch (error) {
    const typedError =
      error instanceof DataIntegrityError
        ? error
        : PROOF_VERIFICATION_ERROR(error instanceof Error ? error.message : String(error));
    return { verified: false, error: typedError };
  }
}

export function startCreateProof(options: JsonDocument, unsecuredDocument: JsonDocument): Buffer {
  const transformedBytes = transform(unsecuredDocument, options);
  const proofConfigBytes = proofConfiguration(options, unsecuredDocument);
  return hash(transformedBytes, proofConfigBytes);
}

export function finishCreateProof(assertion: WebAuthnAssertion, options: JsonDocument): Proof {
  return { ...options, proofValue: encodeProofValue(assertion) } as Proof;
}
