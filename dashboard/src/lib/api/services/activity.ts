import { getList } from '@/lib/api/crud';
import type { ActivityDay, OrgActivity } from '@/types/activity';

type ActivityCategoryCountResponse = {
  category: string;
  count: number;
};

type ActivityDayResponse = {
  by_category: ActivityCategoryCountResponse[];
  count: number;
  date: string;
  level: number;
};

type OrgActivityResponse = {
  categories: string[];
  days: ActivityDayResponse[];
  from: string;
  max_count: number;
  to: string;
  total: number;
};

type GetOrgActivityParams = {
  from: string;
  to: string;
};

function toActivityDay(response: ActivityDayResponse): ActivityDay {
  return {
    byCategory: response.by_category.map((item) => ({
      category: item.category,
      count: item.count,
    })),
    count: response.count,
    date: response.date,
    level: response.level,
  };
}

export async function getOrgActivity(
  orgSlug: string,
  params: GetOrgActivityParams,
): Promise<OrgActivity> {
  const response = await getList<OrgActivityResponse>(
    `/organizations/${encodeURIComponent(orgSlug)}/activity`,
    { params },
  );

  return {
    categories: response.categories,
    days: response.days.map(toActivityDay),
    from: response.from,
    maxCount: response.max_count,
    to: response.to,
    total: response.total,
  };
}
