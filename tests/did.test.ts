// The DID below is a public did:jwk identifier and the expected JWK is its
// (public) decoded form. No private key material is present in this test.

import { resolveDid } from '../src/lib/did';

describe('DID Tests', () => {
  it('resolve JWK DID', () => {
    const jwkDid =
      'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im9kWUZUSTJkRmJKZlE4SE5BcFhCV3hQQWowbEFXWkk4ZXhDZVMzTnk1bDAiLCJ5IjoiclZ4UzNNelg3bDY2QkU2ZHlVZEF1cE5FRURJWnVxRHpVbVNIVmcxOEw2ZyJ9#1';
    const resolved = {
      kty: 'EC',
      crv: 'P-256',
      x: 'odYFTI2dFbJfQ8HNApXBWxPAj0lAWZI8exCeS3Ny5l0',
      y: 'rVxS3MzX7l66BE6dyUdAupNEEDIZuqDzUmSHVg18L6g',
    };
    expect(resolveDid(jwkDid)).toEqual(resolved);
  });
});
