import { apiClient } from '@/lib/api/client';
import { createResource, getList } from '@/lib/api/crud';
import type { ClassificationRuleInput } from '@/schemas/classification-schemas';
import type { ClassificationRule, DataClassLevel, RedactionStrategy } from '@/types/classification';

type ClassificationRuleResponse = {
  field_path: string;
  id: string;
  level: DataClassLevel;
  redaction: RedactionStrategy;
};

type ClassificationResponse = {
  id: string;
  rules: ClassificationRuleResponse[];
};

type AddRuleRequest = {
  field_path: string;
  level: DataClassLevel;
  redaction: RedactionStrategy;
};

function getClassificationEndpoint(orgSlug: string, tenantSlug: string) {
  return `/organizations/${encodeURIComponent(orgSlug)}/tenants/${encodeURIComponent(
    tenantSlug,
  )}/classification`;
}

function toClassificationRule(response: ClassificationRuleResponse): ClassificationRule {
  return {
    fieldPath: response.field_path,
    id: response.id,
    level: response.level,
    redaction: response.redaction,
  };
}

export async function getClassificationRules(
  orgSlug: string,
  tenantSlug: string,
): Promise<ClassificationRule[]> {
  const response = await getList<ClassificationResponse>(
    getClassificationEndpoint(orgSlug, tenantSlug),
  );

  return (response?.rules ?? []).map(toClassificationRule);
}

export async function addClassificationRule(
  orgSlug: string,
  tenantSlug: string,
  payload: ClassificationRuleInput,
): Promise<ClassificationRule> {
  const response = await createResource<ClassificationRuleResponse, AddRuleRequest>(
    `${getClassificationEndpoint(orgSlug, tenantSlug)}/rules`,
    {
      field_path: payload.fieldPath.trim(),
      level: payload.level,
      redaction: payload.redaction,
    },
  );

  return toClassificationRule(response);
}

export async function removeClassificationRule(
  orgSlug: string,
  tenantSlug: string,
  ruleId: string,
): Promise<void> {
  await apiClient.delete(
    `${getClassificationEndpoint(orgSlug, tenantSlug)}/rules/${encodeURIComponent(ruleId)}`,
  );
}
