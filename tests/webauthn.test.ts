import { extractChallenge, verifyProofSignature } from '../src/suites/webauthn/helpers';
import { Webauthn2026Cryptosuite } from '../src/suites/webauthn/webauthn-2026';
import { base64urlToUtf8 } from '../src/lib/utils';

const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: '5Y0MYq7rbQcdKXRPVTl_XCOMEvwUUjD3KLqGCeD5HOo',
  y: 'ucOg3msSa7Wa6rQI-tlQB8rEl0ZEjyfjbWP7XhbvXvA',
};

const ProofValue = {
  authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
  clientData:
    'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTGhCSW1UcmtKQmxSRWlIQ2lsNXhXX25COFpXUWlGdk9kRU9KT0FCZ3lFRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
  signature:
    'MEYCIQCx_E8E72uZyAC-97TmwlnUtfLfTJLA1I4BxPIZRy_8VgIhALM-IzZnvPfdBzCjXpd2HuFZdlZogb3_7HtDo23wvVTi',
  userHandle: 'MmY0MjQzM2ItMTAxNC00YjRhLTg0YjEtNTVmNTg0N2I3ODE2',
};

const signedLd = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/data-integrity/v2',
  ],
  type: ['VerifiablePresentation'],
  verifiableCredential: [
    'eyJraWQiOiJkaWQ6a2V5Ono2TWtqb1JocTFqU05KZExpcnVTWHJGRnhhZ3FyenRaYVhIcUhHVVRLSmJjTnl3cCN6Nk1ram9SaHExalNOSmRMaXJ1U1hyRkZ4YWdxcnp0WmFYSHFIR1VUS0piY055d3AiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtqb1JocTFqU05KZExpcnVTWHJGRnhhZ3FyenRaYVhIcUhHVVRLSmJjTnl3cCIsInN1YiI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdpZUNJNklqVlpNRTFaY1RkeVlsRmpaRXRZVWxCV1ZHd3ZXRU5QVFVWMmQxVlZha1F6UzB4eFIwTmxSRFZJVDI4OUlpd2llU0k2SW5WalQyY3piWE5UWVRkWFlUWnlVVWtyZEd4UlFqaHlSV3d3V2tWcWVXWnFZbGRRTjFob1luWllka0U5SWl3aVlXeG5Jam9pUlVORVUwRmZkMTlUU0VFeU5UWWlmUSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJCYW5rSWQiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWNjb3VudElkIjoiMTIzNDU2Nzg5MCIsIklCQU4iOiJERTk5MTIzNDU2Nzg5MDEyMzQ1Njc4IiwiQklDIjoiREVVVERFREJCRVIiLCJiaXJ0aERhdGUiOiIxOTU4LTA4LTE3IiwiZmFtaWx5TmFtZSI6IkRPRSIsImdpdmVuTmFtZSI6IkpPSE4iLCJpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdpZUNJNklqVlpNRTFaY1RkeVlsRmpaRXRZVWxCV1ZHd3ZXRU5QVFVWMmQxVlZha1F6UzB4eFIwTmxSRFZJVDI4OUlpd2llU0k2SW5WalQyY3piWE5UWVRkWFlUWnlVVWtyZEd4UlFqaHlSV3d3V2tWcWVXWnFZbGRRTjFob1luWllka0U5SWl3aVlXeG5Jam9pUlVORVUwRmZkMTlUU0VFeU5UWWlmUSJ9LCJpZCI6InVybjp1dWlkOjNmMDNiN2IyLTEwZTEtNGEzZi04YzJhLTUyNzMwOGJlMTU4ZCIsImlzc3VlZCI6IjIwMjEtMDgtMzFUMDA6MDA6MDBaIiwiaXNzdWVyIjp7ImlkIjoiZGlkOmtleTp6Nk1ram9SaHExalNOSmRMaXJ1U1hyRkZ4YWdxcnp0WmFYSHFIR1VUS0piY055d3AiLCJpbWFnZSI6eyJpZCI6Imh0dHBzOi8vaW1hZ2VzLnNxdWFyZXNwYWNlLWNkbi5jb20vY29udGVudC92MS82MDljMGRkZjk0YmNjMDI3OGE3Y2JkYjQvMTY2MDI5NjE2OTMxMy1LMTU5SzlXWDhKOFBQSkUwMDVIVi9XYWx0K0JvdF9Mb2dvLnBuZz9mb3JtYXQ9MTAwdyIsInR5cGUiOiJJbWFnZSJ9LCJuYW1lIjoiQ0ggQXV0aG9yaXR5IiwidHlwZSI6IlByb2ZpbGUiLCJ1cmwiOiJodHRwczovL2ltYWdlcy5zcXVhcmVzcGFjZS1jZG4uY29tL2NvbnRlbnQvdjEvNjA5YzBkZGY5NGJjYzAyNzhhN2NiZGI0LzE2NjAyOTYxNjkzMTMtSzE1OUs5V1g4SjhQUEpFMDA1SFYvV2FsdCtCb3RfTG9nby5wbmc_Zm9ybWF0PTEwMHcifSwiaXNzdWFuY2VEYXRlIjoiMjAyNi0wMS0xNFQxMDoxNTozMy44MzI5NjQ1MDBaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDI3LTAxLTE0VDEwOjE1OjMzLjgzMjk2NDUwMFoifSwianRpIjoidXJuOnV1aWQ6M2YwM2I3YjItMTBlMS00YTNmLThjMmEtNTI3MzA4YmUxNThkIiwiZXhwIjoxNzk5OTIxNzMzLCJpYXQiOjE3NjgzODU3MzMsIm5iZiI6MTc2ODM4NTczM30.nZ1zzqlS3kyiUvMoAbr1wZtbiPSq_SHss6vvSSLFeqzNbdSxS7ibSS2321o8dxXqeAPdfRIdGtelKQ9mrn1TDQ',
  ],
  id: 'urn:uuid:ef15b2e4-59a4-4301-b16c-9b2febd45e20',
  holder:
    'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im9kWUZUSTJkRmJKZlE4SE5BcFhCV3hQQWowbEFXWkk4ZXhDZVMzTnk1bDAiLCJ5IjoiclZ4UzNNelg3bDY2QkU2ZHlVZEF1cE5FRURJWnVxRHpVbVNIVmcxOEw2ZyJ9',
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'webauthn-2026',
    created: '2026-01-20T10:34:14.021014500Z',
    challenge: '5a32268a-0072-4d9d-b465-a1587cb44c5c',
    domain: 'http://localhost:7003/openid4vc/verify',
    proofPurpose: 'authentication',
    verificationMethod:
      'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im9kWUZUSTJkRmJKZlE4SE5BcFhCV3hQQWowbEFXWkk4ZXhDZVMzTnk1bDAiLCJ5IjoiclZ4UzNNelg3bDY2QkU2ZHlVZEF1cE5FRURJWnVxRHpVbVNIVmcxOEw2ZyJ9#0',
    proofValue: {
      signature:
        'MEUCIQD9eahY2eu2wwMo4QGBkC-dAqvYr-r6K6D3SArdYTzSuAIgVtIsVphVDw_KnI_VycPpQ2APaE3DLwxU0dExlK00ydA',
      authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
      clientData:
        'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiU3lWUmZaLVJJd2d1ZW15c2p6Tk5SX2pYNUhsVjRBRzNEbkxiLVNOY0hDbyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
    },
  },
};

describe('Webauthn2026Cryptosuite', () => {
  it('verify fido signature with JWK public key', async () => {
    expect(await verifyProofSignature(ProofValue, jwk)).toBe(true);
  });
  it('extracted challenge check', async () => {
    const expected = 'LhBImTrkJBlREiHCil5xW_nB8ZWQiFvOdEOJOABgyEE';
    expect(extractChallenge(ProofValue.clientData)).toBe(expected);
  });
  it('verify signed LD document', async () => {
    const result = await Webauthn2026Cryptosuite.verify(signedLd);
    expect(result.verified).toBe(true);
  });
  it('changed presentation should fail verification', async () => {
    const tamperedLd = { ...signedLd, holder: 'did:example:tampered' };
    const result = await Webauthn2026Cryptosuite.verify(tamperedLd);
    expect(result.verified).toBe(false);
  });
  it('changed clientData should fail verification', async () => {
    const temperedData = base64urlToUtf8(ProofValue.clientData).replace(
      'webauthn.get',
      'webauthn.create'
    );
    const tamperedClientData = Buffer.from(temperedData).toString('base64url');
    const tamperedProofValue = { ...ProofValue, clientData: tamperedClientData };
    const isValid = await verifyProofSignature(tamperedProofValue, jwk);
    expect(isValid).toBe(false);
  });
});
