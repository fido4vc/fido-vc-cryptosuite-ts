// Base on @simplewebauthn/server's verifySignatureJwk

import { webcrypto } from 'crypto';
import { unwrapEC2Signature } from './unwrap-ec2-signature';

/**
 * Import a JWK key using Node.js crypto
 */
async function importKey(opts: {
  keyData: webcrypto.JsonWebKey;
  algorithm:
    | webcrypto.AlgorithmIdentifier
    | webcrypto.RsaHashedImportParams
    | webcrypto.EcKeyImportParams;
}): Promise<CryptoKey> {
  const { keyData, algorithm } = opts;
  return crypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
}

/**
 * Verify a signature using an EC2 public key in JWK format
 */
async function verifyEC2(opts: {
  keyData: webcrypto.JsonWebKey;
  signature: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
}): Promise<boolean> {
  const { keyData, signature, data } = opts;

  if (!keyData.crv) {
    throw new Error('JWK was missing crv (EC2)');
  }

  const keyAlgorithm: webcrypto.EcKeyImportParams = {
    name: 'ECDSA',
    namedCurve: keyData.crv,
  };

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  // Determine which SHA algorithm to use for signature verification
  // Default to SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521
  let hashName = 'SHA-256';
  if (keyData.crv === 'P-384') {
    hashName = 'SHA-384';
  } else if (keyData.crv === 'P-521') {
    hashName = 'SHA-512';
  }

  const verifyAlgorithm = {
    name: 'ECDSA',
    hash: { name: hashName },
  };

  return crypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

/**
 * Verify a signature using an OKP public key in JWK format
 */
async function verifyOKP(opts: {
  keyData: webcrypto.JsonWebKey;
  signature: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
}): Promise<boolean> {
  const { keyData, signature, data } = opts;

  if (!keyData.crv) {
    throw new Error('JWK was missing crv (OKP)');
  }

  let _crv: 'Ed25519';
  if (keyData.crv === 'Ed25519') {
    _crv = 'Ed25519';
  } else {
    throw new Error(`Unexpected JWK crv value of ${keyData.crv} (OKP)`);
  }

  const keyAlgorithm = {
    name: _crv,
    namedCurve: _crv,
  };

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  const verifyAlgorithm = {
    name: _crv,
  };

  return crypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

/**
 * Verify a signature using an RSA public key in JWK format
 */
async function verifyRSA(opts: {
  keyData: webcrypto.JsonWebKey;
  signature: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
}): Promise<boolean> {
  const { keyData, signature, data } = opts;

  if (!keyData.alg) {
    throw new Error('JWK was missing alg (RSA)');
  }

  // Determine algorithm name and hash from JWK alg
  let algorithmName: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS';
  let hashName: string;
  let saltLength: number | undefined;

  if (
    keyData.alg === 'RS256' ||
    keyData.alg === 'RS384' ||
    keyData.alg === 'RS512' ||
    keyData.alg === 'RS1'
  ) {
    algorithmName = 'RSASSA-PKCS1-v1_5';
    if (keyData.alg === 'RS256') {
      hashName = 'SHA-256';
    } else if (keyData.alg === 'RS384') {
      hashName = 'SHA-384';
    } else if (keyData.alg === 'RS512') {
      hashName = 'SHA-512';
    } else if (keyData.alg === 'RS1') {
      hashName = 'SHA-1';
    } else {
      throw new Error(`Unexpected RSA alg ${keyData.alg}`);
    }
  } else if (keyData.alg === 'PS256' || keyData.alg === 'PS384' || keyData.alg === 'PS512') {
    algorithmName = 'RSA-PSS';
    if (keyData.alg === 'PS256') {
      hashName = 'SHA-256';
      saltLength = 32;
    } else if (keyData.alg === 'PS384') {
      hashName = 'SHA-384';
      saltLength = 48;
    } else if (keyData.alg === 'PS512') {
      hashName = 'SHA-512';
      saltLength = 64;
    } else {
      throw new Error(`Unexpected RSA-PSS alg ${keyData.alg}`);
    }
  } else {
    throw new Error(`Unsupported RSA algorithm ${keyData.alg}`);
  }

  const keyAlgorithm = {
    name: algorithmName,
    hash: { name: hashName },
  };

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  const verifyAlgorithm = {
    name: algorithmName,
    saltLength,
  };

  return crypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

/**
 * Verify signatures with JWK public key. Supports EC2, OKP, and RSA public keys.
 */
export async function verifyFidoSignature(opts: {
  keyData: webcrypto.JsonWebKey;
  signature: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
}): Promise<boolean> {
  const { keyData, signature, data } = opts;

  if (keyData.kty === 'EC') {
    let unwrappedSignature = signature;
    if (keyData.crv === 'P-256') {
      unwrappedSignature = unwrapEC2Signature(signature, 'P-256');
    } else if (keyData.crv === 'P-384') {
      unwrappedSignature = unwrapEC2Signature(signature, 'P-384');
    } else if (keyData.crv === 'P-521') {
      unwrappedSignature = unwrapEC2Signature(signature, 'P-521');
    }

    return verifyEC2({
      keyData,
      signature: unwrappedSignature,
      data,
    });
  } else if (keyData.kty === 'RSA') {
    return verifyRSA({ keyData, signature, data });
  } else if (keyData.kty === 'OKP') {
    return verifyOKP({ keyData, signature, data });
  }

  throw new Error(`Signature verification with JWK of kty ${keyData.kty} is not supported`);
}
