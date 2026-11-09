import { apiClient } from '@/lib/api/client';
import type {
  OperationInput,
  OperationPreview,
  WorkflowIntegration,
  WorkflowOperation,
} from '@/types/workflows';

type IntegrationResponse = {
  brand: string;
  connecting: string;
  description: string;
  icon: string;
  key: string;
  picture?: string | null;
  sign_in_asks_for?: string | null;
  title: string;
};

type InputFormResponse = {
  block: string;
  choices?: { label: string; tone: string; value: string }[];
  example?: string | null;
  group: string;
  label: string;
  picker?: { depends_on?: string | null; filled_by: string } | null;
  style: string;
  warning?: string | null;
};

type OperationInputResponse = {
  description: string;
  form?: InputFormResponse | null;
  name: string;
  required: boolean;
};

type OperationResponse = {
  ceiling: string;
  description: string;
  effect: string;
  inputs: OperationInputResponse[];
  integration: string;
  needs_account: boolean;
  operation: string;
  outputs: { description: string; path: string }[];
  preview?: OperationPreview | null;
  title: string;
};

function getWorkflowsEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/workflows`;
}

function toIntegration(response: IntegrationResponse): WorkflowIntegration {
  return {
    brand: response.brand,
    connecting: response.connecting,
    description: response.description,
    icon: response.icon,
    key: response.key,
    picture: response.picture ?? null,
    signInAsksFor: response.sign_in_asks_for ?? null,
    title: response.title,
  };
}

function toOperationInput(response: OperationInputResponse): OperationInput {
  const form = response.form;

  return {
    description: response.description,
    form: form
      ? {
          block: form.block,
          choices: form.choices ?? [],
          example: form.example ?? null,
          group: form.group,
          label: form.label,
          picker: form.picker
            ? { dependsOn: form.picker.depends_on ?? null, filledBy: form.picker.filled_by }
            : null,
          style: form.style,
          warning: form.warning ?? null,
        }
      : null,
    name: response.name,
    required: response.required,
  };
}

function toOperation(response: OperationResponse): WorkflowOperation {
  return {
    ceiling: response.ceiling,
    description: response.description,
    effect: response.effect,
    inputs: response.inputs.map(toOperationInput),
    integration: response.integration,
    needsAccount: response.needs_account,
    operation: response.operation,
    outputs: response.outputs,
    preview: response.preview ?? null,
    title: response.title,
  };
}

/** Every integration installed in this deployment. */
export async function getWorkflowIntegrations(orgSlug: string, tenantSlug: string) {
  const { data } = await apiClient.get<IntegrationResponse[]>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/integrations`,
  );

  return data.map(toIntegration);
}

/** Every operation the installed integrations offer. */
export async function getWorkflowOperations(
  orgSlug: string,
  tenantSlug: string,
): Promise<WorkflowOperation[]> {
  const { data } = await apiClient.get<OperationResponse[]>(
    `${getWorkflowsEndpoint(orgSlug, tenantSlug)}/operations`,
  );

  return data.map(toOperation);
}
