import { VerifiablePresentation } from '../types';

export function getProofData(document: VerifiablePresentation) {
  const { proof, ...docWithoutProof } = document;
  if (!proof) throw new Error('Proof is missing in the document');
  const proofObj = Array.isArray(proof) ? proof[0] : proof;
  const { proofValue, ...proofOptions } = proofObj;
  return { proof: proofObj, proofValue, docWithoutProof, proofOptions };
}

export function base64urlToUtf8(base64urlString: string): string {
  return Buffer.from(base64urlString, 'base64url').toString('utf8');
}
