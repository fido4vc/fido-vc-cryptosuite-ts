import { ICryptosuite, VerifiablePresentation } from '../types';
import { Fido4vcCryptosuite } from '../suites/fido4vc/fido4vc-cryptosuite';
import { getProofData } from '../lib/utils';

export const supportedSuites: Map<string, ICryptosuite> = new Map([
  [Fido4vcCryptosuite.name, Fido4vcCryptosuite],
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
