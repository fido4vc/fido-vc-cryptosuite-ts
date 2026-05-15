import { ICryptosuite, VerifiablePresentation } from '../types';
import { Webauthn2026Cryptosuite } from '../suites/webauthn/webauthn-2026';
import { getProofData } from '../lib/utils';

export const supportedSuites: Map<string, ICryptosuite> = new Map([
  [Webauthn2026Cryptosuite.name, Webauthn2026Cryptosuite],
]);

export function getCryptosuite(cryptosuiteName: string): ICryptosuite {
  const suiteObj = supportedSuites.get(cryptosuiteName);
  if (!suiteObj) {
    throw new Error(`Unsupported cryptosuite: ${cryptosuiteName}`);
  }
  return suiteObj;
}

export function getCryptosuiteForDocument(document: VerifiablePresentation): ICryptosuite {
  const cryptosuite = getProofData(document).proof.cryptosuite;
  if (!cryptosuite || typeof cryptosuite !== 'string') {
    throw new Error('Cryptosuite type is missing or invalid in the document proof');
  }
  return getCryptosuite(cryptosuite);
}
