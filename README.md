<p align="center">
  <img src="https://raw.githubusercontent.com/fido4vc/.github/main/assets/fido4vc-logo-color.svg" alt="FIDO4VC" width="180"/>
</p>

# fido-vc-cryptosuite-ts

[![npm version](https://img.shields.io/npm/v/@fido4vc/fido-vc-cryptosuite-ts.svg)](https://www.npmjs.com/package/@fido4vc/fido-vc-cryptosuite-ts)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

> TypeScript reference implementation of the [`fido4vc-jcs-2026`](https://fido4vc.github.io/spec/fido4vc-jcs-2026/) W3C VC Data Integrity cryptosuite.
> Part of the [FIDO4VC project](https://fido4vc.github.io).

A W3C [Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity/) cryptosuite for **FIDO/WebAuthn-signed Verifiable Presentations**.

When a holder presents a VP using a FIDO authenticator (passkey, YubiKey, Touch ID, Windows Hello, …), the resulting WebAuthn assertion is wrapped as a `DataIntegrityProof` on the VP. This package canonicalizes such a document, binds the WebAuthn challenge to the canonicalized bytes, resolves the holder's public key from the proof's DID, and verifies the FIDO signature.

## Features

- **Verification** of VPs whose proof is a FIDO/WebAuthn assertion (`verifyProof`).
- **Proof assembly** helpers for the two-phase WebAuthn flow (`startCreateProof` / `finishCreateProof`) — the actual signature is produced by the authenticator, not by this library.
- JCS canonicalization + SHA-256 hashing of `{proof configuration, document}`, per the `fido4vc-jcs-2026` cryptosuite.
- Pluggable DID / verification-method resolution via the `VerificationMethodResolver` interface; a default resolver supports `did:jwk` and `did:key`.
- Structured, W3C-aligned `DataIntegrityError` reporting.
- No private key material ever touches this library.

## Install

```bash
npm install @fido4vc/fido-vc-cryptosuite-ts
```

Requires **Node.js ≥ 18** (uses the WebCrypto API from `node:crypto`).

- npm: <https://www.npmjs.com/package/@fido4vc/fido-vc-cryptosuite-ts>
- Source: <https://github.com/fido4vc/fido-vc-cryptosuite-ts>

## Usage

### Verify a signed Verifiable Presentation

```ts
import { verifyProof } from '@fido4vc/fido-vc-cryptosuite-ts';

const result = await verifyProof(signedVp);

if (result.verified) {
  // result.verifiedDocument is the VP with the proof removed
  console.log('valid', result.verifiedDocument);
} else {
  // result.error is a DataIntegrityError
  console.error('invalid', result.error);
}
```

`verifyProof` never throws — any failure is captured and returned as
`{ verified: false, error }`.

### Use a custom resolver

By default, `verifyProof` resolves `proof.verificationMethod` with a built-in
resolver supporting `did:jwk` and `did:key`. To support other DID methods or
inject your own key lookup, pass a `VerificationMethodResolver`:

```ts
import { verifyProof, VerificationMethodResolver, JwkPublicKey } from '@fido4vc/fido-vc-cryptosuite-ts';

const myResolver: VerificationMethodResolver = {
  async resolveVerificationMethod(vmUrl: string): Promise<JwkPublicKey> {
    // look up vmUrl however you like and return a public JWK
    return /* JwkPublicKey */;
  },
};

const result = await verifyProof(signedVp, myResolver);
```

### Assemble a proof from a WebAuthn assertion

Signing is a two-phase operation because the signature comes from the FIDO
authenticator:

```ts
import { startCreateProof, finishCreateProof } from '@fido4vc/fido-vc-cryptosuite-ts';

// 1. Compute the bytes the authenticator must sign over (the WebAuthn challenge).
const proofOptions = {
  type: 'DataIntegrityProof',
  cryptosuite: 'fido4vc-jcs-2026',
  proofPurpose: 'authentication',
  verificationMethod: 'did:jwk:eyJ...#0',
};
const hashData = startCreateProof(proofOptions, unsecuredVp);
const challenge = hashData.toString('base64url'); // pass to navigator.credentials.get()

// 2. After the authenticator responds, wrap the assertion into a proof.
const proof = finishCreateProof(
  {
    authenticatorData: assertion.authenticatorData, // Uint8Array
    signature: assertion.signature,                 // Uint8Array
    clientDataJSON: assertion.clientDataJSON,        // Uint8Array
  },
  proofOptions,
);

const signedVp = { ...unsecuredVp, proof };
```

### Resolve a verification method directly

```ts
import { resolver } from '@fido4vc/fido-vc-cryptosuite-ts';

const jwk = await resolver.defaultResolver.resolveVerificationMethod('did:jwk:eyJ...#0');
const didDoc = await resolver.defaultResolver.resolveDid('did:key:zDnae...');
```

## Supported DID methods (default resolver)

| Method     | Status |
|------------|--------|
| `did:jwk`  | ✅ |
| `did:key`  | ✅ |

Other methods can be supported by supplying your own `VerificationMethodResolver`.

## How verification works (`fido4vc-jcs-2026`)

1. Split the `proof` from the secured document.
2. **Transform** — JCS-canonicalize the unsecured document (requires
   `proof.type === "DataIntegrityProof"` and `proof.cryptosuite === "fido4vc-jcs-2026"`).
3. **Proof configuration** — copy the proof options, drop `proofValue`, inject the
   document's `@context`, and JCS-canonicalize.
4. **Hash** — `hashData = sha256(proofConfig) || sha256(transformedDocument)`
   (64 bytes).
5. Decode `proof.proofValue` — a multibase (`u`, base64url) string wrapping a CBOR
   array `[authenticatorData, signature, clientDataJSON]`.
6. **Verify** the WebAuthn assertion:
   - `clientData.type` must be `webauthn.get`;
   - `clientData.challenge` must equal `hashData` (base64url);
   - resolve `proof.verificationMethod` to an EC public JWK;
   - recompute the signed bytes `authenticatorData || sha256(clientDataJSON)` and
     verify `signature` against the resolved key.

Any failure returns `{ verified: false, error }`; success returns
`{ verified: true, verifiedDocument }`.

## Public API

```ts
// Verification
function verifyProof(
  securedDocument: JsonDocument,
  resolver?: VerificationMethodResolver,
): Promise<VerificationResult>;

// Proof assembly (signature is produced externally by the authenticator)
function startCreateProof(options: JsonDocument, unsecuredDocument: JsonDocument): Buffer;
function finishCreateProof(assertion: WebAuthnAssertion, options: JsonDocument): Proof;

const SUITE_NAME = 'fido4vc-jcs-2026';

// Resolution (namespace export)
namespace resolver {
  interface VerificationMethodResolver {
    resolveVerificationMethod(vmUrl: string): Promise<JwkPublicKey>;
  }
  class DidResolver implements VerificationMethodResolver { /* + resolveDid(did) */ }
  const defaultResolver: DidResolver; // did:jwk + did:key
  class ResolverError extends Error {}
}

// Errors
class DataIntegrityError extends Error {} // { type, code, title, detail }
function PROOF_GENERATION_ERROR(detail: string): DataIntegrityError;
function PROOF_TRANSFORMATION_ERROR(detail: string): DataIntegrityError;
function PROOF_VERIFICATION_ERROR(detail: string): DataIntegrityError;

// Types
// JsonDocument, JsonLdDocument, Proof, VerifiablePresentation, VerificationResult,
// WebAuthnAssertion, JwkPublicKey, VerificationMethodResolver, DIDDocument, VerificationMethod
```

> `VerificationMethodResolver` is also re-exported at the top level for convenience,
> alongside the `resolver` namespace.

## Develop locally

Prerequisites: Node.js ≥ 18, npm.

```bash
git clone https://github.com/fido4vc/fido-vc-cryptosuite-ts
cd fido-vc-cryptosuite-ts
npm install
npm run build      # compile TS -> dist/
npm test           # run the Jest suite
```

### Running the tests

```bash
npm test                       # full suite
npm test -- resolver.test      # only resolver tests
npm test -- fido4vc.test       # only cryptosuite tests
```

The fixtures in `tests/` are captured WebAuthn assertion artifacts (public JWK
coordinates, `authenticatorData`, `clientDataJSON`, `signature`) plus a signed
Verifiable Presentation. They drive the verification path end-to-end without a
live FIDO authenticator. WebAuthn assertions and their components are public by
design — there is no secret material here — so the fixtures can be committed and
reused freely.

## Scripts

| Script              | What it does                          |
|---------------------|---------------------------------------|
| `npm run build`     | Compile TypeScript to `dist/`         |
| `npm run watch`     | Compile in watch mode                 |
| `npm run clean`     | Remove `dist/`                        |
| `npm test`          | Run the Jest test suite               |
| `npm run lint`      | Run ESLint                            |
| `npm run lint:fix`  | Run ESLint with `--fix`               |
| `npm run format`    | Format sources with Prettier          |

## Publishing

`prepublishOnly` cleans and rebuilds before every publish, so a fresh `dist/` is
always shipped. The published tarball contains only `dist/`, `README.md`, and
`LICENSE` (see `files` in [package.json](./package.json)).

```bash
npm publish
```

## Related projects

Part of the [FIDO4VC project](https://github.com/fido4vc):

- [fido-vc-middleware](https://github.com/fido4vc/fido-vc-middleware) — Express bridge between FIDO/WebAuthn and the walt.id Wallet API. Consumes this package.
- [fido-vc-verifier-sidecar](https://github.com/fido4vc/fido-vc-verifier-sidecar) — HTTP service exposing this cryptosuite's verification to non-Node verifier stacks.
- [fido-vc-wallet-ui](https://github.com/fido4vc/fido-vc-wallet-ui) — Next.js user-facing wallet UI.

## License

Licensed under the [Apache License 2.0](./LICENSE).
