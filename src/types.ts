import type { webcrypto } from 'crypto';
export type { DIDDocument, VerificationMethod } from 'did-resolver';

export type JwkPublicKey = webcrypto.JsonWebKey;

export interface JsonDocument {
  [key: string]: unknown;
}

export interface JsonLdDocument extends JsonDocument {
  '@context': string | string[] | object | object[];
}

export interface Proof {
  type: string;
  cryptosuite: string;
  verificationMethod: string;
  proofPurpose: string;
  created?: string;
  challenge?: string;
  domain?: string;
  proofValue: string;
}

export interface VerifiablePresentation extends JsonLdDocument {
  type: string | string[];
  verifiableCredential?: unknown[];
  holder?: string;
  proof?: Proof | Proof[];
}

export interface VerificationResult {
  verified: boolean;
  verifiedDocument?: JsonDocument;
  error?: unknown;
}

export interface Cryptosuite {
  name: string;
  verifyProof(document: Record<string, unknown>): Promise<VerificationResult>;
  createProof(document: Record<string, unknown>, options: Record<string, unknown>): Promise<Proof>;
  [key: string]: unknown;
}

export interface WebAuthnAssertion {
  authenticatorData: Uint8Array;
  signature: Uint8Array;
  clientDataJSON: Uint8Array;
}
