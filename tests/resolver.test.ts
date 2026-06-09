// All DIDs and key material in this file are public identifiers — no secret keys are present.
// The did:jwk DID is the holder/verificationMethod from the existing integration fixture.
// The did:key P-256 vector is from the did:key spec.

import { defaultResolver, DidResolver } from '../src/lib/resolver';
import type { DIDDocument } from '../src/types';

const FIXTURE_DID_JWK =
  'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Imp2eXlvaGZBeGF0eVJVQUtHZ3VJRVl3b3dUZlFjTHZDODl0emdxbV9MaW8iLCJ5IjoiU0NWWHJnbE9xTktjOC13WVdxWHNFOHd2WkpIQkVuV0YzLTdTOXBTTlotOCJ9';

// did:key test vector for P-256 (secp256r1) from the did:key specification.
const FIXTURE_DID_KEY_P256 = 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169';
const FIXTURE_DID_KEY_P256_VM_URL = `${FIXTURE_DID_KEY_P256}#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169`;

describe('DidResolver', () => {
  describe('resolveDid (did:jwk)', () => {
    it('returns a DIDDocument for a valid did:jwk', async () => {
      const doc: DIDDocument = await defaultResolver.resolveDid(FIXTURE_DID_JWK);
      expect(doc.id).toBe(FIXTURE_DID_JWK);
      expect(Array.isArray(doc.verificationMethod)).toBe(true);
      expect(doc.verificationMethod!.length).toBeGreaterThan(0);
    });

    it('resolves the verification method with a P-256 JWK', async () => {
      const doc = await defaultResolver.resolveDid(FIXTURE_DID_JWK);
      const vm = (doc.verificationMethod ?? []).find((v) => typeof v !== 'string') as
        | { publicKeyJwk?: { kty?: string; crv?: string } }
        | undefined;
      expect(vm?.publicKeyJwk?.kty).toBe('EC');
      expect(vm?.publicKeyJwk?.crv).toBe('P-256');
    });

    it('throws for an unsupported DID method', async () => {
      await expect(defaultResolver.resolveDid('did:example:123')).rejects.toMatchObject({
        message: expect.stringContaining('did:example:123'),
      });
    });
  });

  describe('resolveDid (did:key)', () => {
    it('returns a DIDDocument for a valid did:key (P-256)', async () => {
      const doc = await defaultResolver.resolveDid(FIXTURE_DID_KEY_P256);
      expect(doc.id).toBe(FIXTURE_DID_KEY_P256);
      expect(Array.isArray(doc.verificationMethod)).toBe(true);
    });
  });

  describe('resolveVerificationMethod (did:jwk)', () => {
    it('returns the JWK for the correct #0 fragment', async () => {
      const jwk = await defaultResolver.resolveVerificationMethod(FIXTURE_DID_JWK + '#0');
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(typeof jwk.x).toBe('string');
      expect(typeof jwk.y).toBe('string');
    });

    it('throws for a wrong fragment', async () => {
      await expect(
        defaultResolver.resolveVerificationMethod(FIXTURE_DID_JWK + '#1')
      ).rejects.toMatchObject({ message: expect.stringContaining('#1') });
    });

    it('throws for a vmUrl with no fragment', async () => {
      await expect(
        defaultResolver.resolveVerificationMethod(FIXTURE_DID_JWK)
      ).rejects.toMatchObject({ message: expect.stringContaining('fragment') });
    });
  });

  describe('resolveVerificationMethod (did:key P-256)', () => {
    it('returns a P-256 JWK for the correct fragment', async () => {
      const jwk = await defaultResolver.resolveVerificationMethod(FIXTURE_DID_KEY_P256_VM_URL);
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
      expect(typeof jwk.x).toBe('string');
      expect(typeof jwk.y).toBe('string');
    });
  });

  describe('VerificationMethodResolver interface (injection seam)', () => {
    it('DidResolver implements VerificationMethodResolver', () => {
      const r = new DidResolver();
      expect(typeof r.resolveDid).toBe('function');
      expect(typeof r.resolveVerificationMethod).toBe('function');
    });
  });
});
