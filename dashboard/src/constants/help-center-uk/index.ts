import { AGENTS_UK } from '@/constants/help-center-uk/agents';
import { AUTHENTICATION_UK } from '@/constants/help-center-uk/authentication';
import { AUTOMATION_UK } from '@/constants/help-center-uk/automation';
import { GETTING_STARTED_UK } from '@/constants/help-center-uk/getting-started';
import { MONITORING_UK } from '@/constants/help-center-uk/monitoring';
import { ORGANIZATIONS_UK } from '@/constants/help-center-uk/organizations';
import { ROUTING_UK } from '@/constants/help-center-uk/routing';
import { SECURITY_UK } from '@/constants/help-center-uk/security';
import { TENANTS_UK } from '@/constants/help-center-uk/tenants';
import type { HelpArticleTranslation } from '@/constants/help-center-uk/types';

/** Category slug to Ukrainian title. */
export const HELP_CENTER_UK_CATEGORY_TITLES: Record<string, string> = {
  'getting-started': 'Початок роботи',
  'organizations-and-billing': 'Організації та оплата',
  tenants: 'Тенанти',
  'authentication-and-security': 'Автентифікація та безпека',
  'routing-and-proxy': 'Маршрутизація та проксі',
  'ai-agents': 'ШІ-агенти',
  'automation-and-integrations': 'Автоматизація та інтеграції',
  'crypto-and-signing-keys': 'Криптографія та ключі підпису',
  'monitoring-and-troubleshooting': 'Моніторинг і усунення несправностей',
  'account-settings': 'Налаштування облікового запису',
};

/** Article path (`category/topic[/sub-topic]`) to its Ukrainian text. */
export const HELP_CENTER_UK_ARTICLES: Record<string, HelpArticleTranslation> = {
  ...GETTING_STARTED_UK,
  ...ORGANIZATIONS_UK,
  ...TENANTS_UK,
  ...AUTHENTICATION_UK,
  ...SECURITY_UK,
  ...ROUTING_UK,
  ...AGENTS_UK,
  ...AUTOMATION_UK,
  ...MONITORING_UK,
};
