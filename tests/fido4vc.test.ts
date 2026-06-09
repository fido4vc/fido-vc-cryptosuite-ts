// Captured WebAuthn assertion artifacts used to drive the verification tests
// end-to-end without a live FIDO authenticator. The JWK below has only its
// public coordinates (kty/crv/x/y — no `d`), and a WebAuthn signature plus
// its associated authenticatorData/clientData are public by design. These
// are reference fixtures, not credentials — there is no secret material here.

import { finishCreateProof, verifyProof } from '../src';
import { proofConfiguration } from '../src/cryptosuite/algorithms';

// Raw authenticator response produced by a real FIDO2 device.
const authenticatorResponseJSON = {
  authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
  clientDataJSON:
    'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicXpfRXAtQkJJZk4yOHlnd0d1ZWRUTC1ndVhMZWlVekNFWGJBWEZiVnQ2MTZQYUVpeFNkdUxTWGdSQTN4NWhhTG12Qi1EdHBCdzZMYk8zdVBxUnFOZmciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature:
    'MEQCIGwigQcHklGS0dZ3cvhgmQLAhCbrwECWZuuZEPcTsZQfAiAQbhcRozZ6Huv6xM-n1k0mOYd28OI0I_sYthH819skyA',
  userHandle: 'TXlLZXkx',
};

const signedLd = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2',
  ],
  type: ['VerifiablePresentation'],
  holder:
    'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Imp2eXlvaGZBeGF0eVJVQUtHZ3VJRVl3b3dUZlFjTHZDODl0emdxbV9MaW8iLCJ5IjoiU0NWWHJnbE9xTktjOC13WVdxWHNFOHd2WkpIQkVuV0YzLTdTOXBTTlotOCJ9#0',
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'fido4vc-jcs-2026',
    proofPurpose: 'authentication',
    verificationMethod:
      'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Imp2eXlvaGZBeGF0eVJVQUtHZ3VJRVl3b3dUZlFjTHZDODl0emdxbV9MaW8iLCJ5IjoiU0NWWHJnbE9xTktjOC13WVdxWHNFOHd2WkpIQkVuV0YzLTdTOXBTTlotOCJ9#0',
    created: '2026-05-29T12:52:50.089443145Z',
    challenge: '5c567af7-cffa-489a-85fb-8dea23375024',
    domain: 'http://waltid-issuer-api:7002/draft13',
    proofValue:
      'ug9hAWCVJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XYx0AAAAA2EBYRjBEAiBsIoEHB5JRktHWd3L4YJkCwIQm68BAlmbrmRD3E7GUHwIgEG4XEaM2eh7r-sTPp9ZNJjmHdvDiNCP7GLYR_NfbJMjYQFixeyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicXpfRXAtQkJJZk4yOHlnd0d1ZWRUTC1ndVhMZWlVekNFWGJBWEZiVnQ2MTZQYUVpeFNkdUxTWGdSQTN4NWhhTG12Qi1EdHBCdzZMYk8zdVBxUnFOZmciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  },
};

describe('Fido4vcCryptosuite', () => {
  describe('verifyProof', () => {
    it('verifies a real signed document end-to-end', async () => {
      const result = await verifyProof(signedLd);
      expect(result.verified).toBe(true);
      expect(result.verifiedDocument).toBeDefined();
    });

    it('fails when the document body is tampered', async () => {
      const tampered = { ...signedLd, holder: 'did:example:tampered' };
      const result = await verifyProof(tampered);
      expect(result.verified).toBe(false);
    });

    it('fails when proofValue has a wrong multibase prefix', async () => {
      const tampered = { ...signedLd, proof: { ...signedLd.proof, proofValue: 'zINVALID' } };
      const result = await verifyProof(tampered);
      expect(result.verified).toBe(false);
    });

    it('fails when proof is missing', async () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { proof: _proof, ...noProof } = signedLd;
      const result = await verifyProof(noProof);
      expect(result.verified).toBe(false);
    });
  });

  describe('finishCreateProof', () => {
    it('encodes real assertion data into the expected proofValue', () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { proofValue: _pv, ...proofOptions } = signedLd.proof;
      const assertion = {
        authenticatorData: Buffer.from(authenticatorResponseJSON.authenticatorData, 'base64url'),
        signature: Buffer.from(authenticatorResponseJSON.signature, 'base64url'),
        clientDataJSON: Buffer.from(authenticatorResponseJSON.clientDataJSON, 'base64url'),
      };
      const proof = finishCreateProof(assertion, proofOptions);
      expect(proof.proofValue).toBe(signedLd.proof.proofValue);
    });
  });

  describe('proofConfiguration', () => {
    it('strips proofValue and injects @context from the document', () => {
      const config = JSON.parse(proofConfiguration(signedLd.proof, signedLd).toString('utf8'));
      expect(config.proofValue).toBeUndefined();
      expect(config['@context']).toEqual(signedLd['@context']);
    });
  });
});
