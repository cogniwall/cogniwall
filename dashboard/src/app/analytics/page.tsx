import { AnalyticsCards } from "@/components/analytics-cards";
import { EvaluationsChart } from "@/components/charts/evaluations-chart";
import { TopRulesChart } from "@/components/charts/top-rules-chart";
import { TopAgentsChart } from "@/components/charts/top-agents-chart";
import { queryAnalytics } from "@/lib/queries";

export default async function AnalyticsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;
  const data = await queryAnalytics({
    from: params.from,
    to: params.to,
    interval: (params.interval as "hour" | "day" | "week") || "hour",
  });

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Analytics</h2>
      <AnalyticsCards summary={data.summary} />
      <EvaluationsChart data={data.over_time} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <TopRulesChart data={data.top_rules} />
        <TopAgentsChart data={data.top_blocked_agents} />
      </div>
    </div>
  );
}
