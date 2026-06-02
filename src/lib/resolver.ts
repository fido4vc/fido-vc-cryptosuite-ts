import { Resolver } from 'did-resolver';
import type { DIDDocument, VerificationMethod } from 'did-resolver';
import { getDidJwkResolver } from '@sphereon/ssi-sdk-ext.did-resolver-jwk';
import { getResolver as getDidKeyResolver } from '@sphereon/ssi-sdk-ext.did-resolver-key';
import type { JwkPublicKey } from '../types';

export type { DIDDocument, VerificationMethod };

export interface VerificationMethodResolver {
  resolveVerificationMethod(vmUrl: string): Promise<JwkPublicKey>;
}

export class ResolverError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResolverError';
  }
}

export class DidResolver implements VerificationMethodResolver {
  private readonly resolver: Resolver;

  constructor() {
    this.resolver = new Resolver({ ...getDidJwkResolver(), ...getDidKeyResolver() });
  }

  async resolveDid(did: string): Promise<DIDDocument> {
    const result = await this.resolver.resolve(did);
    if (result.didResolutionMetadata?.error || !result.didDocument) {
      throw new ResolverError(
        `Failed to resolve DID "${did}": ${result.didResolutionMetadata?.error ?? 'no document returned'}`
      );
    }
    return result.didDocument;
  }

  async resolveVerificationMethod(vmUrl: string): Promise<JwkPublicKey> {
    const hashIndex = vmUrl.indexOf('#');
    if (hashIndex === -1) {
      throw new ResolverError(`verificationMethod "${vmUrl}" must contain a fragment (#)`);
    }
    const did = vmUrl.slice(0, hashIndex);
    const fragment = vmUrl.slice(hashIndex + 1);

    const doc = await this.resolveDid(did);
    const vms: VerificationMethod[] = (doc.verificationMethod ?? []).flatMap((vm) =>
      typeof vm === 'string' ? [] : [vm]
    );

    const vm = vms.find(
      (v) => v.id === vmUrl || v.id === '#' + fragment || v.id.endsWith('#' + fragment)
    );

    if (!vm) {
      throw new ResolverError(
        `Verification method "${vmUrl}" not found in DID document for "${did}"`
      );
    }

    if (!vm.publicKeyJwk) {
      throw new ResolverError(`Verification method "${vmUrl}" has no publicKeyJwk`);
    }

    return vm.publicKeyJwk;
  }
}

export const defaultResolver = new DidResolver();
