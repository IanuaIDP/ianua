import type { ReenteredProof } from '@/types/auth';

export type ReenteredProofBody = {
  code?: string;
  method: 'password';
  password: string;
};

export function toReenteredProofBody(proof: ReenteredProof): ReenteredProofBody {
  return { code: proof.code, method: 'password', password: proof.password };
}

export type FreshProofBody = {
  code?: string;
  password: string;
};

export function toFreshProofBody(proof: ReenteredProof): FreshProofBody {
  return { code: proof.code, password: proof.password };
}
