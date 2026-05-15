import { JwkPublicKey } from '../types';
import { base64urlToUtf8 } from './utils';

export function resolveDid(did: string): JwkPublicKey {
  const [prefix, method, identifier] = did.split(':');
  if (prefix !== 'did') throw new Error('Invalid DID prefix');
  if (method === 'jwk') return resolveJwkDid(identifier);
  throw new Error(`Unsupported DID method: ${method}`);
}

function resolveJwkDid(identifier: string): JwkPublicKey {
  const base = identifier.split('#')[0];
  const decoded = base64urlToUtf8(base);
  const jwk = JSON.parse(decoded);
  if (!jwk.kty) throw new Error('Invalid JWK DID: missing "kty" field');
  return jwk;
}
