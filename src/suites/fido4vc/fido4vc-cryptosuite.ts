import { createHash } from 'crypto';
import { ICryptosuite, JsonLdDocument, VerifiablePresentation } from '../../types';
import { getProofData } from '../../lib/utils';
import JCSCanonicalize from 'canonicalize';
import { extractProofValue, extractChallenge, verifyProofSignature } from './helpers';
import { resolveDid } from '../../lib/did';

const name = 'fido4vc-jcs-2026';

export async function canonicalize(document: VerifiablePresentation) {
  const { proofOptions, docWithoutProof } = getProofData(document);
  const canonical = JCSCanonicalize(docWithoutProof)!;
  const canonicalProofOptions = JCSCanonicalize(proofOptions)!;

  const hash = createHash('sha256');
  hash.update(canonical);
  hash.update(canonicalProofOptions);
  return hash.digest();
}

export async function sign<ProofValue>(_options: JsonLdDocument): Promise<ProofValue> {
  throw new Error(`${name} doesn't support signing.`);
}

export async function verify(document: VerifiablePresentation) {
  try {
    const proofValue = extractProofValue(document);
    const challenge = await canonicalize(document).then((buf) => buf.toString('base64url'));
    const extractedChallenge = extractChallenge(proofValue.clientData);
    if (challenge !== extractedChallenge) {
      throw new Error('Challenge mismatch');
    }
    const publicKey = resolveDid(getProofData(document).proof.verificationMethod);
    const isSignatureValid = await verifyProofSignature(proofValue, publicKey);
    if (!isSignatureValid) {
      throw new Error('Invalid signature');
    }
    return { verified: true };
  } catch (error) {
    return { verified: false, error: (error as Error).message };
  }
}

export const Fido4vcCryptosuite: ICryptosuite = {
  name,
  canonicalize,
  sign,
  verify,
};
