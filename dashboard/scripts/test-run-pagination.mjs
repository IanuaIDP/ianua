import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';

const source = readFileSync(new URL('../src/lib/api/services/runs.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function service(responses) {
  const calls = [];
  const exports = {};
  const crud = {
    getList: async (endpoint, options) => {
      calls.push({ kind: 'list', endpoint, options });
      return responses.page;
    },
    getById: async (endpoint, id) => {
      calls.push({ kind: 'detail', endpoint, id });
      return responses.detail;
    },
  };
  runInNewContext(compiled, {
    exports,
    require: (name) => {
      if (name === '@/lib/api/crud') return crud;
      if (name === '@/lib/api/client') return { apiClient: {} };
      if (name === '@/utils/classification') return { toDataClassLevel: (value) => value };
      throw new Error(`Unexpected dependency: ${name}`);
    },
  });
  return { api: exports, calls };
}

const summary = {
  id: 'run-1',
  agent_id: 'agent-1',
  provider_id: 'provider-1',
  goal: 'Read the report',
  exposure: 'public',
  purpose: ['read'],
  status: 'completed',
  max_steps: 20,
};

test('summary pages preserve opaque cursors without fetching or inventing trace steps', async () => {
  const { api, calls } = service({
    page: { items: [summary], next_cursor: 'next+/=&', limit: 20 },
  });
  const page = await api.getAgentRuns('org /', 'tenant /', 'agent /', {
    after: 'prior+/=&',
    limit: 20,
  });

  assert.equal(page.items[0].id, 'run-1');
  assert.equal(page.items[0].status, 'Completed');
  assert.equal('steps' in page.items[0], false);
  assert.equal(page.nextCursor, 'next+/=&');
  assert.equal(page.limit, 20);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].kind, 'list');
  assert.equal(calls[0].options.params.after, 'prior+/=&');
  assert.equal(calls[0].options.params.limit, 20);
  assert.match(calls[0].endpoint, /org%20%2F\/tenants\/tenant%20%2F\/agents\/agent%20%2F\/runs$/);
});

test('the final page has no next cursor and defaults to twenty summaries', async () => {
  const { api, calls } = service({ page: { items: [], next_cursor: null, limit: 20 } });
  const page = await api.getAgentRuns('org', 'tenant', 'agent');

  assert.equal(page.items.length, 0);
  assert.equal(page.nextCursor, null);
  assert.equal(calls[0].options.params.limit, 20);
  assert.equal(calls[0].options.params.after, undefined);
});

test('an explicit detail read retrieves and maps the full trace', async () => {
  const { api, calls } = service({
    detail: {
      ...summary,
      steps: [
        {
          seq: 1,
          detail: 'Read completed',
          outcome: 'answered',
          tool: 'read',
          arguments: '{"id":1}',
        },
      ],
    },
  });
  const detail = await api.getAgentRun('org', 'tenant', 'agent', 'run /');

  assert.equal(calls.length, 1);
  assert.equal(calls[0].kind, 'detail');
  assert.equal(calls[0].id, 'run%20%2F');
  assert.equal(detail.steps.length, 1);
  assert.equal(detail.steps[0].seq, 1);
  assert.equal(detail.steps[0].outcome, 'answered');
  assert.equal(detail.steps[0].arguments, '{"id":1}');
});
