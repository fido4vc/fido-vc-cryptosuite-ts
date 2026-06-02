import type { Cryptosuite, JsonDocument } from '../types';
import { Fido4vcCryptosuite } from '../suites/fido4vc/fido4vc-jcs-2026';

export const supportedSuites: Record<string, Cryptosuite> = {
  [Fido4vcCryptosuite.name]: Fido4vcCryptosuite,
};

export function getCryptosuite(name: string): Cryptosuite {
  const suite = supportedSuites[name];
  if (!suite) throw new Error(`Unsupported cryptosuite: ${name}`);
  return suite;
}

export function extractProof(document: JsonDocument): Record<string, unknown> | null {
  if (!document.proof) {
    throw new Error('Proof field is missing in the document');
  }
  const proof = Array.isArray(document.proof) ? document.proof[0] : document.proof;
  return typeof proof === 'object' ? proof : null;
}

export function getCryptosuiteForDocument(document: JsonDocument): Cryptosuite {
  const proof = extractProof(document);
  if (!proof) throw new Error('Proof field is missing or invalid in the document');
  const cryptosuite = proof.cryptosuite;
  if (!cryptosuite || typeof cryptosuite !== 'string') {
    throw new Error('Cryptosuite type is missing or invalid in the document proof');
  }
  return getCryptosuite(cryptosuite);
}