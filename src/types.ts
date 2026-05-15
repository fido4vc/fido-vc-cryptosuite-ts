import type { webcrypto } from 'crypto';

export type JwkPublicKey = webcrypto.JsonWebKey;
export type ProofValueType = string | number | JsonDocument;

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
  proofValue: ProofValueType;
  created?: string;
  challenge?: string;
  domain?: string;
}

export interface VerifiablePresentation extends JsonLdDocument {
  type: string | string[];
  verifiableCredential?: unknown[];
  holder?: string;
  proof?: Proof | Proof[];
}

export interface SignOptions {
  document: JsonLdDocument;
  privateKey: JwkPublicKey;
  verificationMethod: string;
  proofPurpose: string;
  challenge?: string;
  domain?: string;
}

export interface VerificationResult {
  verified: boolean;
  error?: string;
}

export interface ICryptosuite {
  name: string;
  canonicalize(document: JsonDocument): Promise<Buffer<ArrayBuffer>>;
  sign<T extends ProofValueType>(options: JsonLdDocument): Promise<T>;
  verify(options: JsonLdDocument): Promise<VerificationResult>;
}
