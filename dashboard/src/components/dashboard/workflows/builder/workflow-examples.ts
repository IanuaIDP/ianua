import type { WorkflowProposal } from '@/types/workflow-graph';

export type WorkflowExample = {
  id: 'alert' | 'morning' | 'review' | 'risky';
  /** The integrations it needs an account for. */
  needs: string[];
  proposal: WorkflowProposal;
};

/** Examples in the same shape a model proposes, so both become a draft the same way. */
export const WORKFLOW_EXAMPLES: WorkflowExample[] = [
  {
    id: 'alert',
    needs: ['slack'],
    proposal: {
      edges: [],
      notes: [],
      steps: [
        {
          inputs: [{ name: 'text', path: 'trigger.message' }],
          integration: 'slack',
          key: 'tell-the-team',
          kind: 'action',
          operation: 'post-message',
          title: 'Tell the team',
        },
      ],
      trigger: { kind: 'webhook' },
    },
  },
  {
    id: 'morning',
    needs: ['google-calendar', 'slack'],
    proposal: {
      edges: [{ from: 'read-the-day', port: 'next', to: 'post-it' }],
      notes: [],
      steps: [
        {
          inputs: [],
          integration: 'google-calendar',
          key: 'read-the-day',
          kind: 'action',
          operation: 'list-events',
          title: "Read today's meetings",
        },
        {
          inputs: [{ name: 'text', path: 'read-the-day' }],
          integration: 'slack',
          key: 'post-it',
          kind: 'action',
          operation: 'post-message',
          title: 'Post it in Slack',
        },
      ],
      trigger: { cron: '0 8 * * 1-5', kind: 'schedule' },
    },
  },
  {
    id: 'risky',
    needs: [],
    proposal: {
      edges: [
        { from: 'look-up', port: 'next', to: 'is-locked' },
        { from: 'is-locked', port: 'when_false', to: 'ask' },
        { from: 'ask', port: 'next', to: 'sign-out' },
      ],
      notes: [],
      steps: [
        {
          inputs: [],
          integration: 'ianua',
          key: 'look-up',
          kind: 'action',
          operation: 'find-person',
          title: 'Look up the person',
        },
        {
          equals: 'locked',
          kind: 'condition',
          key: 'is-locked',
          path: 'look-up.status',
          title: 'Are they already locked?',
        },
        {
          class: 'admin',
          key: 'ask',
          kind: 'approval',
          summary: 'Sign this person out everywhere after a risky sign-in?',
          title: 'A person says yes',
        },
        {
          inputs: [],
          integration: 'ianua',
          key: 'sign-out',
          kind: 'action',
          operation: 'sign-out',
          title: 'Sign them out everywhere',
        },
      ],
      trigger: { kind: 'manual' },
    },
  },
  {
    id: 'review',
    needs: [],
    proposal: {
      edges: [{ from: 'wait-a-day', port: 'next', to: 'remind' }],
      notes: [],
      steps: [
        {
          key: 'wait-a-day',
          kind: 'wait',
          seconds: 86_400,
          title: 'Wait a day',
        },
        {
          inputs: [],
          integration: 'ianua',
          key: 'remind',
          kind: 'action',
          operation: 'notify',
          title: 'Remind them',
        },
      ],
      trigger: { kind: 'manual' },
    },
  },
];
