"use client";

import { Database, ShieldAlert, ShieldCheck, TrendingUp } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: { value: number; positive: boolean };
  variant?: "default" | "danger" | "success" | "primary";
}

function StatCard({ title, value, subtitle, icon, trend, variant = "default" }: StatCardProps) {
  const variantStyles = {
    default: "text-foreground",
    danger: "text-danger",
    success: "text-success",
    primary: "text-primary",
  };

  return (
    <Card className="bg-card border-border">
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">{title}</p>
            <p className={`text-3xl font-bold ${variantStyles[variant]}`}>{value.toLocaleString()}</p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          <div className="p-2.5 rounded-lg bg-secondary">{icon}</div>
        </div>
        {trend && (
          <div className="mt-3 flex items-center gap-1.5">
            <TrendingUp className={`h-3.5 w-3.5 ${trend.positive ? "text-success" : "text-danger"}`} />
            <span className={`text-xs font-medium ${trend.positive ? "text-success" : "text-danger"}`}>
              {trend.positive ? "+" : ""}{trend.value}%
            </span>
            <span className="text-xs text-muted-foreground">vs last 24h</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface StatsPanelProps {
  totalTrackedIPs: number;
  maliciousCount: number;
  suspiciousCount: number;
  cleanCount: number;
}

export function StatsPanel({
  totalTrackedIPs,
  maliciousCount,
  suspiciousCount,
  cleanCount,
}: StatsPanelProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      <StatCard
        title="Total Tracked IPs"
        value={totalTrackedIPs}
        subtitle="In threat database"
        icon={<Database className="h-5 w-5 text-primary" />}
        trend={{ value: 12, positive: true }}
        variant="default"
      />
      <StatCard
        title="Malicious IPs"
        value={maliciousCount}
        subtitle="Active threats"
        icon={<ShieldAlert className="h-5 w-5 text-danger" />}
        trend={{ value: 8, positive: false }}
        variant="danger"
      />
      <StatCard
        title="Clean IPs"
        value={cleanCount}
        subtitle="No threats detected"
        icon={<ShieldCheck className="h-5 w-5 text-success" />}
        variant="success"
      />
    </div>
  );
}
