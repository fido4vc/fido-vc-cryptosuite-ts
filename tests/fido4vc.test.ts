// Captured WebAuthn assertion artifacts used to drive the verification tests
// end-to-end without a live FIDO authenticator. The JWK below has only its
// public coordinates (kty/crv/x/y — no `d`), and a WebAuthn signature plus
// its associated authenticatorData/clientData are public by design. These
// are reference fixtures, not credentials — there is no secret material here.

import { extractChallenge, verifyProofSignature } from '../src/suites/fido4vc/helpers';
import { Fido4vcCryptosuite } from '../src/suites/fido4vc/fido4vc-cryptosuite';
import { base64urlToUtf8 } from '../src/lib/utils';

const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'soI1HETmYs6tpGxlFrcLhUgy_tMtlUlEYgGfAETKIp4',
  y: 'x6RH1cRM6kSzCD5IGFWRHSToIn-LZpSp_CLMZHzJmqo',
};

const ProofValue = {
  authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAw',
  clientData:
    'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMk04VEhuRElZQi0xbl9ZUmF3ZF9oRHVkYTFURGFyd3BYUXhrVkw4Qk8ydyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
  signature:
    'MEUCIEMVGtAX7rYYMHtF95wdxx3xkNwmHlJnxFBTzUKKZI1QAiEApOnlMGtky_xy7E06wq6gy1NEe7Glssrr7f08QylDH88',
};

const signedLd = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/data-integrity/v2',
  ],
  type: ['VerifiablePresentation'],
  verifiableCredential: [
    'eyJraWQiOiJkaWQ6a2V5Ono2TWtqb1JocTFqU05KZExpcnVTWHJGRnhhZ3FyenRaYVhIcUhHVVRLSmJjTnl3cCN6Nk1ram9SaHExalNOSmRMaXJ1U1hyRkZ4YWdxcnp0WmFYSHFIR1VUS0piY055d3AiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtqb1JocTFqU05KZExpcnVTWHJGRnhhZ3FyenRaYVhIcUhHVVRLSmJjTnl3cCIsInN1YiI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SWxBdE1qVTJJaXdpZUNJNkluTnZTVEZJUlZSdFdYTTJkSEJIZUd4R2NtTk1hRlZuZVY5MFRYUnNWV3hGV1dkSFprRkZWRXRKY0RRaUxDSjVJam9pZURaU1NERmpVazAyYTFONlEwUTFTVWRHVjFKSVUxUnZTVzR0VEZwd1UzQmZRMHhOV2toNlNtMXhieUo5IiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkJhbmtJZCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJhY2NvdW50SWQiOiIxMjM0NTY3ODkwIiwiSUJBTiI6IkRFOTkxMjM0NTY3ODkwMTIzNDU2NzgiLCJCSUMiOiJERVVUREVEQkJFUiIsImJpcnRoRGF0ZSI6IjE5NTgtMDgtMTciLCJmYW1pbHlOYW1lIjoiRE9FIiwiZ2l2ZW5OYW1lIjoiSk9ITiIsImlkIjoiZGlkOmp3azpleUpyZEhraU9pSkZReUlzSW1OeWRpSTZJbEF0TWpVMklpd2llQ0k2SW5OdlNURklSVlJ0V1hNMmRIQkhlR3hHY21OTWFGVm5lVjkwVFhSc1ZXeEZXV2RIWmtGRlZFdEpjRFFpTENKNUlqb2llRFpTU0RGalVrMDJhMU42UTBRMVNVZEdWMUpJVTFSdlNXNHRURnB3VTNCZlEweE5Xa2g2U20xeGJ5SjkifSwiaWQiOiJ1cm46dXVpZDpmOTMyYWFiNy04NGM0LTRiOTAtYmJiNi1lNTI0NmZmMTQwMzUiLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6a2V5Ono2TWtqb1JocTFqU05KZExpcnVTWHJGRnhhZ3FyenRaYVhIcUhHVVRLSmJjTnl3cCIsIm5hbWUiOiJDSCBBdXRob3JpdHkiLCJ0eXBlIjoiUHJvZmlsZSIsImltYWdlIjp7ImlkIjoiaHR0cHM6Ly9pbWFnZXMuc3F1YXJlc3BhY2UtY2RuLmNvbS9jb250ZW50L3YxLzYwOWMwZGRmOTRiY2MwMjc4YTdjYmRiNC8xNjYwMjk2MTY5MzEzLUsxNTlLOVdYOEo4UFBKRTAwNUhWL1dhbHQrQm90X0xvZ28ucG5nP2Zvcm1hdD0xMDB3IiwidHlwZSI6IkltYWdlIn0sInVybCI6Imh0dHBzOi8vaW1hZ2VzLnNxdWFyZXNwYWNlLWNkbi5jb20vY29udGVudC92MS82MDljMGRkZjk0YmNjMDI3OGE3Y2JkYjQvMTY2MDI5NjE2OTMxMy1LMTU5SzlXWDhKOFBQSkUwMDVIVi9XYWx0K0JvdF9Mb2dvLnBuZz9mb3JtYXQ9MTAwdyJ9LCJpc3N1YW5jZURhdGUiOiIyMDI2LTA1LTE4VDE1OjMzOjUyLjk5NDMxMzE4NloiLCJleHBpcmF0aW9uRGF0ZSI6IjIwMjctMDUtMThUMTU6MzM6NTIuOTk0NDUzMDU5WiJ9LCJqdGkiOiJ1cm46dXVpZDpmOTMyYWFiNy04NGM0LTRiOTAtYmJiNi1lNTI0NmZmMTQwMzUiLCJleHAiOjE4MTA2NTQ0MzIsImlhdCI6MTc3OTExODQzMiwibmJmIjoxNzc5MTE4NDMyfQ.p74fJ1NFzW5rKQfiVzCtsStJNBFYaq8-bIuJuorwDa855vcI4k3e-54Bm_bfxQgcCa7CWOBg47_VsFCENGxPCw',
  ],
  id: 'urn:uuid:e1838b78-48f6-4e50-86f5-d321dee64cdb',
  holder:
    'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InNvSTFIRVRtWXM2dHBHeGxGcmNMaFVneV90TXRsVWxFWWdHZkFFVEtJcDQiLCJ5IjoieDZSSDFjUk02a1N6Q0Q1SUdGV1JIU1RvSW4tTFpwU3BfQ0xNWkh6Sm1xbyJ9',
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'fido4vc-jcs-2026',
    created: '2026-05-19T14:20:54.026876301Z',
    challenge: 'bbe3631b-ad07-4eed-aca2-a3dde0ca7795',
    domain: 'http://waltid-verifier-api:7003/openid4vc/verify',
    proofPurpose: 'authentication',
    verificationMethod:
      'did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InNvSTFIRVRtWXM2dHBHeGxGcmNMaFVneV90TXRsVWxFWWdHZkFFVEtJcDQiLCJ5IjoieDZSSDFjUk02a1N6Q0Q1SUdGV1JIU1RvSW4tTFpwU3BfQ0xNWkh6Sm1xbyJ9#0',
    proofValue: {
      signature:
        'MEUCIEMVGtAX7rYYMHtF95wdxx3xkNwmHlJnxFBTzUKKZI1QAiEApOnlMGtky_xy7E06wq6gy1NEe7Glssrr7f08QylDH88',
      authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAw',
      clientData:
        'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMk04VEhuRElZQi0xbl9ZUmF3ZF9oRHVkYTFURGFyd3BYUXhrVkw4Qk8ydyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
    },
  },
};

describe('Fido4vcCryptosuite', () => {
  it('verify fido signature with JWK public key', async () => {
    expect(await verifyProofSignature(ProofValue, jwk)).toBe(true);
  });
  it('extracted challenge check', async () => {
    const expected = '2M8THnDIYB-1n_YRawd_hDuda1TDarwpXQxkVL8BO2w';
    expect(extractChallenge(ProofValue.clientData)).toBe(expected);
  });
  it('verify signed LD document', async () => {
    const result = await Fido4vcCryptosuite.verify(signedLd);
    expect(result.verified).toBe(true);
  });
  it('changed presentation should fail verification', async () => {
    const tamperedLd = { ...signedLd, holder: 'did:example:tampered' };
    const result = await Fido4vcCryptosuite.verify(tamperedLd);
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
