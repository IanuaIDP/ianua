import type { ModelProvider, ModelProviderTestState } from '@/types/model-provider';

export function deriveTestState(provider: ModelProvider): ModelProviderTestState | undefined {
  if (!provider.lastTestStatus || !provider.lastTestedAt) {
    return undefined;
  }

  if (provider.lastTestStatus === 'passed') {
    return { result: { ok: true, sample: '' }, status: 'success', testedAt: provider.lastTestedAt };
  }

  return {
    message: provider.lastTestMessage ?? '',
    status: 'error',
    testedAt: provider.lastTestedAt,
  };
}

export function getFailureMessage(testState: ModelProviderTestState | undefined) {
  if (testState?.status === 'error') {
    return testState.message || undefined;
  }

  if (testState?.status === 'success' && !testState.result.ok) {
    return testState.result.sample || undefined;
  }

  return undefined;
}
