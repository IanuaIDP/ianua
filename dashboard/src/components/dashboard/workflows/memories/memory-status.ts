import type { Memory } from '@/types/memory';
import type { ModelProvider } from '@/types/model-provider';

/**
 * Whether a memory's model has gone: it keeps its texts and takes no new ones.
 * `providers` is what could be read; a reader who may not see them learns nothing.
 */
export function hasLostItsModel(memory: Memory, providers: ModelProvider[] | undefined) {
  if (!providers || memory.embeddingSource !== 'provider') {
    return false;
  }

  const provider = providers.find((candidate) => candidate.id === memory.providerId);

  return !provider || provider.embeddingModel !== memory.embeddingModel;
}
