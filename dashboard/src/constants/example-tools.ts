import type { RegisterToolInput } from '@/schemas/tool-schemas';
import type { Route } from '@/types/route';

type ExampleRoute = Pick<Route, 'id' | 'methods' | 'pathPattern'>;

const WILDCARD_ENDING = '/*';

/// A small set of tools to start from.
///
/// Registering a tool by hand asks for a JSON schema, which is a fair thing to
/// ask of someone wiring up a real server and a poor first thing to ask of
/// someone finding out what this does. These cover the shapes worth seeing: a
/// harmless read, a write, and a destructive action that a read-only purpose
/// should refuse even when it has been granted. Their paths are relative: the
/// platform refuses a tool its route does not serve, so each one is placed
/// under the route it is added to.
export const EXAMPLE_TOOLS: Omit<RegisterToolInput, 'routeId'>[] = [
  {
    description: 'List the items behind this route.',
    method: 'GET',
    name: 'example_list_items',
    path: '/items',
    schema: JSON.stringify(
      {
        properties: { status: { description: 'Only items in this state', type: 'string' } },
        type: 'object',
      },
      null,
      2,
    ),
  },
  {
    description: 'Comment on an item.',
    method: 'POST',
    name: 'example_comment_on_item',
    path: '/items/{id}/comments',
    schema: JSON.stringify(
      {
        properties: {
          body: { type: 'string' },
          id: { type: 'string' },
        },
        required: ['id', 'body'],
        type: 'object',
      },
      null,
      2,
    ),
  },
  {
    description: 'Delete an item. Here to be refused: a read-only purpose blocks it.',
    method: 'DELETE',
    name: 'example_delete_item',
    path: '/items/{id}',
    schema: JSON.stringify(
      {
        properties: { id: { type: 'string' } },
        required: ['id'],
        type: 'object',
      },
      null,
      2,
    ),
  },
];

/// Whether example tools can sit under this route: only a path ending in `/*`
/// has room below it.
export function canHoldExampleTools(route: ExampleRoute): boolean {
  return route.pathPattern.endsWith(WILDCARD_ENDING);
}

function routeServesMethod(route: ExampleRoute, method: string): boolean {
  const served = route.methods.map((value) => value.toUpperCase());

  return served.length === 0 || served.includes('ANY') || served.includes(method);
}

/// The example tools this route can carry, with their paths placed under it.
export function exampleToolsFor(route: ExampleRoute): RegisterToolInput[] {
  const base = route.pathPattern.slice(0, -WILDCARD_ENDING.length);

  return EXAMPLE_TOOLS.filter((tool) => routeServesMethod(route, tool.method)).map((tool) => ({
    ...tool,
    path: `${base}${tool.path}`,
    routeId: route.id,
  }));
}
