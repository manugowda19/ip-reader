"use client";

import { ShieldAlert, ShieldCheck, Shield, AlertTriangle, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";

interface ActivityItem {
  id: string;
  type: "malicious" | "suspicious" | "clean" | "alert";
  message: string;
  ip?: string;
  timestamp: string;
  first_seen?: string | null;
  last_seen?: string | null;
}

interface ActivityFeedProps {
  activities: ActivityItem[];
}

export function ActivityFeed({ activities }: ActivityFeedProps) {
  const formatTimestamp = (activity: ActivityItem) => {
    const raw =
      activity.last_seen ??
      activity.first_seen ??
      activity.timestamp;

    // Backend may send ISO strings or Unix seconds (from collector; Redis returns strings)
    const num = typeof raw === "number" ? raw : (typeof raw === "string" && /^\d+$/.test(raw) ? parseInt(raw, 10) : NaN);
    const ms = Number.isFinite(num) ? num * 1000 : new Date(raw as string).getTime();
    if (!Number.isFinite(ms)) return activity.timestamp ?? "—";
    const date = new Date(ms);

    const diffMs = Date.now() - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);

    if (diffSec < 30) return "Just now";
    if (diffMin < 1) return `${diffSec}s ago`;
    if (diffMin < 60) return `${diffMin} min ago`;
    if (diffHour < 24) return `${diffHour} h ago`;

    return date.toISOString().replace("T", " ").replace(/\.\d+Z?$/, " UTC");
  };

  const getActivityIcon = (type: ActivityItem["type"]) => {
    switch (type) {
      case "malicious":
        return <ShieldAlert className="h-4 w-4 text-danger" />;
      case "suspicious":
        return <Shield className="h-4 w-4 text-warning" />;
      case "clean":
        return <ShieldCheck className="h-4 w-4 text-success" />;
      case "alert":
        return <AlertTriangle className="h-4 w-4 text-warning" />;
    }
  };

  const getActivityStyles = (type: ActivityItem["type"]) => {
    switch (type) {
      case "malicious":
        return "border-l-danger bg-danger/5";
      case "suspicious":
        return "border-l-warning bg-warning/5";
      case "clean":
        return "border-l-success bg-success/5";
      case "alert":
        return "border-l-warning bg-warning/5";
    }
  };

  return (
    <Card className="bg-card border-border h-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg font-semibold text-card-foreground">Recent Activity</CardTitle>
          <div className="flex items-center gap-1.5 text-muted-foreground">
            <Clock className="h-4 w-4" />
            <span className="text-xs">Real-time</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[320px] px-6 pb-4">
          <div className="space-y-3">
            {activities.map((activity) => (
              <div
                key={activity.id}
                className={`flex items-start gap-3 p-3 rounded-md border-l-2 ${getActivityStyles(activity.type)}`}
              >
                <div className="mt-0.5">{getActivityIcon(activity.type)}</div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground leading-relaxed">{activity.message}</p>
                  {activity.ip && (
                    <p className="text-xs font-mono text-primary mt-1">{activity.ip}</p>
                  )}
                  <p className="text-xs text-muted-foreground mt-1.5">
                    {formatTimestamp(activity)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
