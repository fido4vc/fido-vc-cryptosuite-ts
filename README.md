<p align="center">
  <img src="https://raw.githubusercontent.com/fido4vc/fido4vc.github.io/main/src/assets/fido4vc-logo-color.svg" alt="FIDO4VC" width="180"/>
</p>

# fido-vc-cryptosuite-ts

[![npm version](https://img.shields.io/npm/v/@fido4vc/fido-vc-cryptosuite-ts.svg)](https://www.npmjs.com/package/@fido4vc/fido-vc-cryptosuite-ts)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

> TypeScript reference implementation of the [`fido4vc-jcs-2026`](https://fido4vc.github.io/spec/fido4vc-jcs-2026/) W3C VC Data Integrity cryptosuite.
> Part of the [FIDO4VC project](https://fido4vc.github.io).

A W3C [Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity/) cryptosuite for **FIDO/WebAuthn-signed Verifiable Presentations**.

When a holder presents a VP using a FIDO authenticator (Passkey, YubiKey, Touch ID, Windows Hello, …), the resulting WebAuthn assertion is wrapped as a Data Integrity proof on the VP. This package canonicalizes such documents, validates the WebAuthn challenge binding, and verifies the FIDO signature against the public key resolved from the proof's DID.

## Features

- W3C VC Data Integrity-shaped `ICryptosuite` interface (`canonicalize` / `sign` / `verify`).
- Pluggable cryptosuite registry — register additional suites alongside the built-in one.
- Built-in suite: **`fido4vc-jcs-2026`** — verifies VPs whose proof is a FIDO/WebAuthn assertion.
- DID resolution helpers (currently supports `did:jwk`).
- Zero-config: JCS canonicalization + SHA-256 hashing of `{document, proof options}`.

## Install

Published to npmjs.com as a public scoped package — no auth required.

```bash
npm install @fido4vc/fido-vc-cryptosuite-ts
```

- npm: <https://www.npmjs.com/package/@fido4vc/fido-vc-cryptosuite-ts>
- Source: <https://github.com/fido4vc/fido-vc-cryptosuite-ts>

## Usage

### Verify a Verifiable Presentation

```ts
import { getCryptosuiteForDocument, VerifiablePresentation } from '@fido4vc/fido-vc-cryptosuite-ts';

async function verify(vp: VerifiablePresentation) {
  const suite = getCryptosuiteForDocument(vp);
  const result = await suite.verify(vp);
  // { verified: true } | { verified: false, error: '...' }
  return result;
}
```

`getCryptosuiteForDocument` reads `proof.cryptosuite` from the document and returns the matching registered suite, or throws if the name is not registered.

### Use a specific suite directly

```ts
import { Fido4vcCryptosuite } from '@fido4vc/fido-vc-cryptosuite-ts';

// Compute the challenge a FIDO authenticator must sign over
const challenge = await Fido4vcCryptosuite.canonicalize(unsignedVp);

// Later, verify the assertion-signed VP
const result = await Fido4vcCryptosuite.verify(signedVp);
```

> Note: `fido4vc-jcs-2026` is verify-only by design — the signature comes from the FIDO authenticator, not from this library. Calling `sign(...)` will throw.

### Resolve a DID

```ts
import { did } from '@fido4vc/fido-vc-cryptosuite-ts';

const jwk = did.resolveDid('did:jwk:eyJ...'); // returns the JWK public key
```

## Supported cryptosuites

| Name             | Sign | Verify | Notes |
|------------------|------|--------|-------|
| `fido4vc-jcs-2026`  | ❌   | ✅     | FIDO2/WebAuthn assertions over JCS-canonicalized VP |

## Supported DID methods

| Method     | Status |
|------------|--------|
| `did:jwk`  | ✅ |

## How verification works (`fido4vc-jcs-2026`)

1. Strip the `proof` from the VP; JCS-canonicalize the document and the proof options separately.
2. SHA-256 hash them in sequence — this is the **expected challenge**.
3. Extract `clientData.challenge` from the proof value and confirm it equals the expected challenge.
4. Resolve `proof.verificationMethod` (DID) to a JWK public key.
5. Recompute the WebAuthn signed bytes (`authenticatorData || sha256(clientData)`) and verify the signature against the resolved key.

Any failure returns `{ verified: false, error }`; success returns `{ verified: true }`.

## Public API

```ts
export interface ICryptosuite {
  name: string;
  canonicalize(document: JsonDocument): Promise<Buffer>;
  sign<T>(document: JsonLdDocument): Promise<T>;
  verify(document: JsonLdDocument): Promise<VerificationResult>;
}

export function getCryptosuite(name: string): ICryptosuite;
export function getCryptosuiteForDocument(vp: VerifiablePresentation): ICryptosuite;

export const Fido4vcCryptosuite: ICryptosuite;
export const did: { resolveDid(did: string): JwkPublicKey };

// Types: JsonDocument, JsonLdDocument, Proof, VerifiablePresentation,
//        SignOptions, VerificationResult, JwkPublicKey, ProofValueType
```

## Develop locally

Prerequisites: Node.js ≥ 18, npm.

```bash
git clone https://github.com/fido4vc/fido-vc-cryptosuite-ts
cd fido-vc-cryptosuite-ts
npm install
npm run build      # compile TS -> dist/
npm test           # run Jest test suite
```

### Running the tests

```bash
npm test                       # full suite
npm test -- --watch            # watch mode
npm test -- did.test           # only DID tests
npm test -- fido4vc.test       # only cryptosuite tests
```

The test fixtures in `tests/` are captured WebAuthn assertion artifacts
(public JWK coordinates, `authenticatorData`, `clientData`, `signature`)
plus a signed Verifiable Presentation. They drive the verification path
end-to-end without needing a live FIDO authenticator. None of the values
are private keys — WebAuthn assertions and their components are public
by design — so the fixtures can be committed and reused freely.

## Scripts

| Script              | What it does                                  |
|---------------------|-----------------------------------------------|
| `npm run build`     | Compile TypeScript to `dist/`                 |
| `npm run watch`     | Compile in watch mode                         |
| `npm run clean`     | Remove `dist/`                                |
| `npm test`          | Run Jest tests                                |
| `npm run lint`      | Run ESLint                                    |
| `npm run lint:fix`  | Run ESLint with `--fix`                       |
| `npm run format`    | Format source with Prettier                   |

## Publishing

`prepublishOnly` cleans and rebuilds before publish, so a fresh `dist/` is always shipped. The published tarball contains only `dist/`, `README.md`, and `LICENSE` (see `files` in [package.json](./package.json)).

```bash
npm publish
```

For private registries, configure `publishConfig.registry` in `package.json` accordingly.

## Related projects

Part of the [FIDO4VC project](https://github.com/fido4vc):

- [fido-vc-middleware](https://github.com/fido4vc/fido-vc-middleware) — Express bridge between FIDO/WebAuthn and the walt.id Wallet API. Consumes this package.
- [fido-vc-verifier-sidecar](https://github.com/fido4vc/fido-vc-verifier-sidecar) — HTTP service exposing this cryptosuite's verification to non-Node verifier stacks.
- [fido-vc-wallet-ui](https://github.com/fido4vc/fido-vc-wallet-ui) — Next.js user-facing wallet UI.

## License

Licensed under the [Apache License 2.0](./LICENSE).
