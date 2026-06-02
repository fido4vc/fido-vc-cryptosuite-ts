export class DataIntegrityError extends Error {
  readonly type: string;
  readonly code: number;
  readonly title: string;
  readonly detail: string;

  constructor(opts: { type: string; code: number; title: string; detail: string }) {
    super(opts.detail);
    this.name = 'DataIntegrityError';
    this.type = opts.type;
    this.code = opts.code;
    this.title = opts.title;
    this.detail = opts.detail;
  }
}

const BASE = 'https://w3id.org/security#';

export function PROOF_GENERATION_ERROR(detail: string): DataIntegrityError {
  return new DataIntegrityError({
    type: `${BASE}PROOF_GENERATION_ERROR`,
    code: 1,
    title: 'Proof Generation Error',
    detail,
  });
}

export function PROOF_TRANSFORMATION_ERROR(detail: string): DataIntegrityError {
  return new DataIntegrityError({
    type: `${BASE}PROOF_TRANSFORMATION_ERROR`,
    code: 2,
    title: 'Proof Transformation Error',
    detail,
  });
}

export function PROOF_VERIFICATION_ERROR(detail: string): DataIntegrityError {
  return new DataIntegrityError({
    type: `${BASE}PROOF_VERIFICATION_ERROR`,
    code: 3,
    title: 'Proof Verification Error',
    detail,
  });
}
