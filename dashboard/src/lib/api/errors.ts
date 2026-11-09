import { isAxiosError } from 'axios';

type ApiErrorBody = {
  error?: unknown;
  message?: unknown;
};

export function getApiErrorMessage(error: unknown, fallbackMessage: string) {
  if (isAxiosError<ApiErrorBody>(error)) {
    const message = error.response?.data?.message;

    if (typeof message === 'string' && message.trim()) {
      return message;
    }

    return fallbackMessage;
  }

  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }

  return fallbackMessage;
}

/** Whether the platform could not be reached or failed, so a link's state is unknown. */
export function isServiceUnavailableError(error: unknown) {
  if (isAxiosError(error)) {
    return !error.response || error.response.status >= 500;
  }

  return error instanceof TypeError;
}

/** Whether the API refused because the thing already exists. */
export function isConflictError(error: unknown) {
  return isAxiosError(error) && error.response?.status === 409;
}

/** The HTTP status the API answered, when it answered at all. */
export function getApiErrorStatus(error: unknown) {
  return isAxiosError(error) ? error.response?.status : undefined;
}

/** Whether the API refused because a code from the person's second factor is missing. */
export function isStepUpRequiredError(error: unknown) {
  return isAxiosError<ApiErrorBody>(error) && error.response?.data?.error === 'step_up_required';
}

/**
 * Evaluates an ordered list of [condition, message] checks and returns the
 * message for the first truthy condition, or `undefined` if none match.
 *
 * Useful for deriving a single display error message from several possible
 * failure states (e.g. missing org context, missing permission, query error)
 * that should be shown with priority ordering.
 */
export function deriveErrorMessage(
  ...checks: Array<[condition: unknown, message: string]>
): string | undefined {
  for (const [condition, message] of checks) {
    if (condition) {
      return message;
    }
  }

  return undefined;
}
