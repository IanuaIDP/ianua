import { useTranslations } from 'next-intl';

import { PATH_REWRITE_MODES, ROUTE_POLICY_KINDS } from '@/constants/route';
import type { SelectOption } from '@/types/dashboard';
import type { PathRewrite, PathRewriteMode, RoutePolicy, RoutePolicyKind } from '@/types/route';
import { getRoutePolicyKind } from '@/utils/route';

/** The choices of the route forms and the way a route reads in the table, in the current language. */
export function useRouteOptions() {
  const t = useTranslations('dashboard.routes');

  const policyKindOptions: (SelectOption & { value: RoutePolicyKind })[] = ROUTE_POLICY_KINDS.map(
    (kind) => ({ label: t(`policy.options.${kind}`), value: kind }),
  );
  const pathRewriteOptions: (SelectOption & { value: PathRewriteMode })[] = PATH_REWRITE_MODES.map(
    (mode) => ({ label: t(`rewrite.modes.${mode}`), value: mode }),
  );

  function policyLabel(policy: RoutePolicy) {
    const kind = getRoutePolicyKind(policy);
    const label = t(`policy.kinds.${kind}`);

    if (typeof policy === 'string') {
      return label;
    }

    if ('RequireSystemPermission' in policy) {
      return `${label} (${policy.RequireSystemPermission.length})`;
    }

    if ('RequireCustomPermission' in policy) {
      return `${label} (${policy.RequireCustomPermission.length})`;
    }

    return `${label} (${policy.RequireScope.length})`;
  }

  function pathRewriteLabel(pathRewrite: PathRewrite) {
    return pathRewrite.mode === 'template'
      ? pathRewrite.template
      : t(`rewrite.table.${pathRewrite.mode === 'strip_prefix' ? 'strip_prefix' : 'keep'}`);
  }

  return { pathRewriteLabel, pathRewriteOptions, policyKindOptions, policyLabel };
}
