export const CARD_WIDTH = 240;
export const CARD_HEIGHT = 84;
export const COLUMN_SPACING = 300;
export const ROW_SPACING = 130;
export const GRID_SIZE = 20;
export const LOOP_PADDING = 24;
export const LOOP_HEADER_HEIGHT = 52;

export const PORT_OFFSET_Y = { next: 42, when_false: 58, when_true: 26 } as const;

export const MAX_STEPS = 64;
export const MAX_ARROWS = 256;
export const MAX_POINT = 20000;

export const MIN_ZOOM = 0.4;
export const MAX_ZOOM = 1.4;

export const MAX_APPROVAL_WINDOW_SECONDS = 7 * 24 * 60 * 60;
export const MAX_WAIT_SECONDS = 30 * 24 * 60 * 60;
export const MAX_RUN_LIMIT_SECONDS = 31 * 24 * 60 * 60;
export const DEFAULT_RUN_LIMIT_SECONDS = 24 * 60 * 60;
export const MAX_CONDITION_CLAUSES = 32;
export const MAX_MAPPED_FIELDS = 64;
export const MAX_AGENT_STEPS = 50;
export const MAX_LOOP_ITEMS = 1000;
export const MAX_LOOP_AT_ONCE = 10;
export const MAX_BANNED_WORDS = 200;

export const HIGH_RISK_EFFECTS = ['admin', 'configure', 'delete', 'financial', 'undeclared'];
export const ACTION_CLASSES = [
  'undeclared',
  'read',
  'write',
  'communicate',
  'delete',
  'configure',
  'financial',
  'admin',
];

export const DATA_LEVELS = ['public', 'internal', 'confidential', 'restricted'];
export const COMPANY_INTEGRATION = 'ianua';

export const TRIGGER_KEY = 'trigger';

// The API refuses a graph with no step, so a draft with none is saved holding this
// empty step. It is never drawn, and the first real step replaces it.
export const EMPTY_DRAFT_KEY = 'ianua-empty-draft';
export const EMPTY_DRAFT_NAME = 'Empty draft';
