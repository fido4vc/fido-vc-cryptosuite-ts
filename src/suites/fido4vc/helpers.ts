import { createHash } from 'crypto';
import { JwkPublicKey, VerifiablePresentation } from '../../types';
import { base64urlToUtf8, getProofData } from '../../lib/utils';
import { verifyFidoSignature } from './verify-signature-jwk';

interface ProofValue {
  clientData: string;
  authenticatorData: string;
  signature: string;
}

export function extractProofValue(document: VerifiablePresentation): ProofValue {
  const { proofValue } = getProofData(document);
  if (!proofValue || typeof proofValue !== 'object')
    throw new Error('Invalid type of proofValue in document');
  const { clientData, authenticatorData, signature } = proofValue;
  if (!clientData || !authenticatorData || !signature) {
    throw new Error('Missing fields in proofValue');
  }
  if (
    typeof clientData !== 'string' ||
    typeof authenticatorData !== 'string' ||
    typeof signature !== 'string'
  ) {
    throw new Error('Invalid types in proofValue fields');
  }
  return { clientData, authenticatorData, signature };
}

export async function verifyProofSignature(
  proofValue: ProofValue,
  publicKey: JwkPublicKey
): Promise<boolean> {
  const clientDataBuffer = Buffer.from(proofValue.clientData, 'base64url');
  const clientDataHash = createHash('sha256').update(clientDataBuffer).digest();
  const authDataBuffer = Buffer.from(proofValue.authenticatorData, 'base64url');
  const data = Buffer.concat([authDataBuffer, clientDataHash]);
  const signatureBuffer = Buffer.from(proofValue.signature, 'base64url');
  return await verifyFidoSignature({ keyData: publicKey, signature: signatureBuffer, data });
}

export function extractChallenge(clientData: string): string {
  const clientDataDecoded = base64urlToUtf8(clientData);
  const clientDataJSON = JSON.parse(clientDataDecoded);
  if (!clientDataJSON.challenge) {
    throw new Error('Challenge not found in clientData');
  }
  return clientDataJSON.challenge;
}
