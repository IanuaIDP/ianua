export type DataClassLevel = 'Public' | 'Internal' | 'Confidential' | 'Restricted';

export type RedactionStrategy = 'Remove' | 'Mask' | 'Hash';

export type ClassificationRule = {
  fieldPath: string;
  id: string;
  level: DataClassLevel;
  redaction: RedactionStrategy;
};

export type ClassificationRuleAction = 'Remove';
