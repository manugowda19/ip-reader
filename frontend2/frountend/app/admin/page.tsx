"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { StatsPanel } from "@/components/stats-panel";
import { MaliciousIPsTable, type TopIP } from "@/components/malicious-ips-table";
import { ActivityFeed } from "@/components/activity-feed";
import { RefreshCw, Trash2, Plus, Rss, Loader2, AlertCircle, CheckCircle, Upload, Search } from "lucide-react";

type BackendStats = { malicious_ips: number; clean_ips: number; total_tracked_ips: number };
type ActivityItem = {
  id: string;
  type: "malicious" | "suspicious" | "clean" | "alert";
  message: string;
  ip?: string;
  timestamp: string;
  first_seen?: string | null;
  last_seen?: string | null;
};

type FeedsResponse = { feeds: Record<string, string> };
type CollectResult = {
  ips_count: number;
  duration_seconds: number;
  feed_results: { name: string; ips_count: number; error: string | null }[];
  error: string | null;
};
type CollectStatus = {
  last_run: {
    last_run: number;
    ips_count: number;
    duration_seconds: number;
    feed_count: number;
  } | null;
};
type BulkExtractResponse = {
  total_extracted: number;
  ips: string[];
};
type BulkSubmitResponse = {
  total_submitted: number;
  source: string;
  label: string;
};

export default function AdminPage() {
  const [feeds, setFeeds] = useState<Record<string, string>>({});
  const [loadingFeeds, setLoadingFeeds] = useState(true);
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [adding, setAdding] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [collectResult, setCollectResult] = useState<CollectResult | null>(null);
  const [lastRun, setLastRun] = useState<CollectStatus["last_run"]>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [bulkText, setBulkText] = useState("");
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkExtracted, setBulkExtracted] = useState<string[]>([]);
  const [bulkSource, setBulkSource] = useState("");
  const [bulkLabel, setBulkLabel] = useState<"malicious" | "clean">("malicious");
  const [bulkSubmitting, setBulkSubmitting] = useState(false);
  const [bulkSubmitResult, setBulkSubmitResult] = useState<BulkSubmitResponse | null>(null);
  const [stats, setStats] = useState<BackendStats | null>(null);
  const [topIps, setTopIps] = useState<TopIP[]>([]);
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [manualFeeds, setManualFeeds] = useState<Record<string, { label: string; ip_count: number; added_at: string }>>({});

  const loadFeeds = async () => {
    setLoadingFeeds(true);
    try {
      const res = await fetch("/api/admin/feeds", { cache: "no-store" });
      if (res.ok) {
        const data = (await res.json()) as FeedsResponse;
        setFeeds(data.feeds ?? {});
      }
    } finally {
      setLoadingFeeds(false);
    }
  };

  const loadCollectStatus = async () => {
    try {
      const res = await fetch("/api/admin/collect/status", { cache: "no-store" });
      if (res.ok) {
        const data = (await res.json()) as CollectStatus;
        setLastRun(data.last_run ?? null);
      }
    } finally {
      setStatusLoading(false);
    }
  };

  const loadManualFeeds = async () => {
    try {
      const res = await fetch("/api/admin/manual_feeds", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setManualFeeds(data.manual_feeds ?? {});
      }
    } catch {
      // ignore
    }
  };

  const handleRemoveManualFeed = async (name: string) => {
    try {
      const res = await fetch(`/api/admin/manual_feeds/${encodeURIComponent(name)}`, { method: "DELETE" });
      if (res.ok) {
        await Promise.all([loadManualFeeds(), loadStats()]);
      }
    } catch {
      // ignore
    }
  };

  const loadStats = async () => {
    try {
      const [statsRes, topRes, actRes] = await Promise.all([
        fetch("/api/stats", { cache: "no-store" }),
        fetch("/api/top", { cache: "no-store" }),
        fetch("/api/activity", { cache: "no-store" }),
      ]);
      if (statsRes.ok) setStats(await statsRes.json());
      if (topRes.ok) setTopIps(await topRes.json());
      if (actRes.ok) setActivities(await actRes.json());
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadFeeds();
    loadCollectStatus();
    loadStats();
    loadManualFeeds();
    const interval = setInterval(loadStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleAddFeed = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = newName.trim();
    const url = newUrl.trim();
    if (!name || !url) return;
    setAdding(true);
    try {
      const res = await fetch("/api/admin/feeds", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, url }),
      });
      if (res.ok) {
        const data = (await res.json()) as FeedsResponse;
        setFeeds(data.feeds ?? {});
        setNewName("");
        setNewUrl("");
      }
    } finally {
      setAdding(false);
    }
  };

  const handleRemoveFeed = async (name: string) => {
    try {
      const res = await fetch(`/api/admin/feeds/${encodeURIComponent(name)}`, { method: "DELETE" });
      if (res.ok) {
        const data = (await res.json()) as FeedsResponse;
        setFeeds(data.feeds ?? {});
      }
    } catch {
      // ignore
    }
  };

  const handleRunCollect = async () => {
    setCollecting(true);
    setCollectResult(null);
    try {
      const res = await fetch("/api/admin/collect", { method: "POST" });
      const data = (await res.json()) as CollectResult;
      setCollectResult(data);
      if (res.ok && !data.error) {
        await loadCollectStatus();
      }
    } finally {
      setCollecting(false);
    }
  };

  const handleBulkExtract = async () => {
    if (!bulkText.trim()) return;
    setBulkLoading(true);
    setBulkExtracted([]);
    setBulkSubmitResult(null);
    try {
      const res = await fetch("/api/admin/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: bulkText }),
      });
      if (res.ok) {
        const data = (await res.json()) as BulkExtractResponse;
        setBulkExtracted(data.ips);
      }
    } finally {
      setBulkLoading(false);
    }
  };

  const handleBulkSubmit = async () => {
    if (bulkExtracted.length === 0 || !bulkSource.trim()) return;
    setBulkSubmitting(true);
    setBulkSubmitResult(null);
    try {
      const res = await fetch("/api/admin/bulk/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips: bulkExtracted, source: bulkSource, label: bulkLabel }),
      });
      if (res.ok) {
        const data = (await res.json()) as BulkSubmitResponse;
        setBulkSubmitResult(data);
        // Refresh everything
        await Promise.all([loadStats(), loadFeeds(), loadCollectStatus(), loadManualFeeds()]);
        // Clear the form
        setBulkText("");
        setBulkExtracted([]);
        setBulkSource("");
        setBulkLabel("malicious");
      }
    } finally {
      setBulkSubmitting(false);
    }
  };

  const formatLastRun = (ts: number) => {
    const d = new Date(ts * 1000);
    const now = Date.now();
    const diff = Math.floor((now - d.getTime()) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return d.toLocaleString();
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Admin Panel</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage threat intelligence feeds, monitor stats, and sync data into Redis.
        </p>
      </div>

      {/* Stats Overview */}
      <StatsPanel
        totalTrackedIPs={stats?.total_tracked_ips ?? 0}
        maliciousCount={stats?.malicious_ips ?? 0}
        suspiciousCount={0}
        cleanCount={stats?.clean_ips ?? 0}
      />

      {/* Collector run */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg font-semibold flex items-center gap-2">
              <Rss className="h-5 w-5" />
              Sync feeds to Redis
            </CardTitle>
            <Button
              onClick={handleRunCollect}
              disabled={collecting || Object.keys(feeds).length === 0}
              className="gap-2"
            >
              {collecting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Syncing…
                </>
              ) : (
                <>
                  <RefreshCw className="h-4 w-4" />
                  Run collector
                </>
              )}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {statusLoading ? (
            <p className="text-sm text-muted-foreground">Loading status…</p>
          ) : lastRun ? (
            <div className="flex flex-wrap gap-4 text-sm">
              <span className="text-muted-foreground">Last run: {formatLastRun(lastRun.last_run)}</span>
              <span>IPs written: <strong>{lastRun.ips_count.toLocaleString()}</strong></span>
              <span>Duration: <strong>{lastRun.duration_seconds}s</strong></span>
              <span>Feeds: <strong>{lastRun.feed_count}</strong></span>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No run yet. Click &quot;Run collector&quot; to sync feeds into Redis.</p>
          )}
          {collectResult && (
            <div className={`rounded-lg border p-4 text-sm ${collectResult.error ? "border-destructive/50 bg-destructive/5" : "border-border bg-muted/30"}`}>
              {collectResult.error ? (
                <div className="flex items-center gap-2 text-destructive">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>{collectResult.error}</span>
                </div>
              ) : (
                <div className="flex items-center gap-2 text-foreground">
                  <CheckCircle className="h-4 w-4 shrink-0 text-success" />
                  <span>Stored <strong>{collectResult.ips_count.toLocaleString()}</strong> IPs in <strong>{collectResult.duration_seconds}s</strong>.</span>
                </div>
              )}
              {collectResult.feed_results && collectResult.feed_results.length > 0 && (
                <ul className="mt-2 space-y-1 text-muted-foreground">
                  {collectResult.feed_results.map((f) => (
                    <li key={f.name}>
                      {f.name}: {f.ips_count} IPs{f.error ? ` — ${f.error}` : ""}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Bulk IP Extractor + Submit */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg font-semibold flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Bulk IP Importer
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Step 1: Paste URLs, logs, or any text — IPs will be extracted. Step 2: Label the source and mark as malicious or clean, then submit to Redis.
          </p>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* Step 1: Extract */}
          <div className="space-y-3">
            <h4 className="text-sm font-semibold text-foreground">Step 1 — Paste &amp; Extract</h4>
            <Textarea
              placeholder={"Paste links, logs, or raw IPs here...\ne.g.\nhttps://malware-c2.example.com/callback?src=192.168.1.100\n45.33.32.156 - suspicious scan detected\n103.224.182.250"}
              className="min-h-[130px] font-mono text-sm"
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
            />
            <Button
              onClick={handleBulkExtract}
              disabled={bulkLoading || !bulkText.trim()}
              className="gap-2"
            >
              {bulkLoading ? (
                <><Loader2 className="h-4 w-4 animate-spin" /> Extracting…</>
              ) : (
                <><Search className="h-4 w-4" /> Extract IPs</>
              )}
            </Button>
          </div>

          {/* Extracted IPs display */}
          {bulkExtracted.length > 0 && (
            <>
              <div className="rounded-lg border border-border p-3">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium text-muted-foreground">
                    Extracted IPs ({bulkExtracted.length})
                  </h4>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs"
                    onClick={() => navigator.clipboard.writeText(bulkExtracted.join("\n"))}
                  >
                    Copy all
                  </Button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {bulkExtracted.map((ip) => (
                    <span key={ip} className="font-mono text-xs bg-muted px-2 py-1 rounded">{ip}</span>
                  ))}
                </div>
              </div>

              {/* Step 2: Label & Submit */}
              <div className="space-y-3 rounded-lg border border-border p-4 bg-muted/20">
                <h4 className="text-sm font-semibold text-foreground">Step 2 — Label &amp; Submit to Redis</h4>
                <div className="grid gap-2">
                  <Label htmlFor="bulk-source">Source name</Label>
                  <Input
                    id="bulk-source"
                    placeholder="e.g. Phishing Campaign, Incident Report, Honeypot Logs"
                    value={bulkSource}
                    onChange={(e) => setBulkSource(e.target.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label>Classification</Label>
                  <div className="flex gap-3">
                    <Button
                      type="button"
                      variant={bulkLabel === "malicious" ? "default" : "outline"}
                      size="sm"
                      className={bulkLabel === "malicious" ? "bg-red-600 hover:bg-red-700" : ""}
                      onClick={() => setBulkLabel("malicious")}
                    >
                      <AlertCircle className="h-4 w-4 mr-1" />
                      Malicious
                    </Button>
                    <Button
                      type="button"
                      variant={bulkLabel === "clean" ? "default" : "outline"}
                      size="sm"
                      className={bulkLabel === "clean" ? "bg-green-600 hover:bg-green-700" : ""}
                      onClick={() => setBulkLabel("clean")}
                    >
                      <CheckCircle className="h-4 w-4 mr-1" />
                      Clean
                    </Button>
                  </div>
                </div>
                <Button
                  onClick={handleBulkSubmit}
                  disabled={bulkSubmitting || !bulkSource.trim()}
                  className="gap-2"
                >
                  {bulkSubmitting ? (
                    <><Loader2 className="h-4 w-4 animate-spin" /> Submitting…</>
                  ) : (
                    <><Upload className="h-4 w-4" /> Submit {bulkExtracted.length} IPs as {bulkLabel}</>
                  )}
                </Button>
                {bulkSubmitResult && (
                  <div className="flex items-center gap-2 text-sm text-green-400">
                    <CheckCircle className="h-4 w-4" />
                    Submitted <strong>{bulkSubmitResult.total_submitted}</strong> IPs
                    as <strong>{bulkSubmitResult.label}</strong> from &quot;{bulkSubmitResult.source}&quot;
                  </div>
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Two feed tables side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Table 1: Link Feeds (URL-based) */}
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg font-semibold flex items-center gap-2">
              <Rss className="h-5 w-5" />
              Link Feeds
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              URL-based feeds fetched by the collector.
            </p>
          </CardHeader>
          <CardContent className="space-y-4">
            <form onSubmit={handleAddFeed} className="space-y-3">
              <div className="grid gap-2">
                <Label htmlFor="feed-name">Feed name</Label>
                <Input
                  id="feed-name"
                  placeholder="e.g. Blocklist.de"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="feed-url">URL</Label>
                <Input
                  id="feed-url"
                  type="url"
                  placeholder="https://..."
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                />
              </div>
              <Button type="submit" disabled={adding || !newName.trim() || !newUrl.trim()} className="gap-2 w-full">
                {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                Add feed
              </Button>
            </form>

            {loadingFeeds ? (
              <p className="text-sm text-muted-foreground">Loading feeds…</p>
            ) : Object.keys(feeds).length === 0 ? (
              <p className="text-sm text-muted-foreground">No link feeds configured.</p>
            ) : (
              <div className="max-h-[350px] overflow-auto rounded-lg border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>URL</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {Object.entries(feeds).map(([name, url]) => (
                      <TableRow key={name}>
                        <TableCell className="font-medium text-sm">{name}</TableCell>
                        <TableCell className="max-w-[200px] truncate text-muted-foreground text-xs font-mono" title={url}>
                          <a href={url} target="_blank" rel="noopener noreferrer" className="hover:underline">{url}</a>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive hover:text-destructive h-7 w-7"
                            onClick={() => handleRemoveFeed(name)}
                            aria-label={`Remove ${name}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Table 2: Manual Feeds (Bulk IP imports) */}
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg font-semibold flex items-center gap-2">
              <Upload className="h-5 w-5" />
              Manual Feeds
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              Feeds added via Bulk IP Importer.
            </p>
          </CardHeader>
          <CardContent>
            {Object.keys(manualFeeds).length === 0 ? (
              <p className="text-sm text-muted-foreground">No manual feeds yet. Use the Bulk IP Importer above to add IPs with a source name.</p>
            ) : (
              <div className="max-h-[400px] overflow-auto rounded-lg border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Source Name</TableHead>
                      <TableHead>Label</TableHead>
                      <TableHead>IPs</TableHead>
                      <TableHead>Added</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {Object.entries(manualFeeds).map(([name, info]) => (
                      <TableRow key={name}>
                        <TableCell className="font-medium text-sm">{name}</TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`text-xs ${
                              info.label === "malicious"
                                ? "bg-red-500/10 text-red-400 border-red-500/30"
                                : "bg-green-500/10 text-green-400 border-green-500/30"
                            }`}
                          >
                            {info.label}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">{info.ip_count}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {info.added_at ? new Date(info.added_at).toLocaleDateString() : "—"}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive hover:text-destructive h-7 w-7"
                            onClick={() => handleRemoveManualFeed(name)}
                            aria-label={`Remove ${name}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Malicious IPs + Activity Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <MaliciousIPsTable ips={topIps} />
        </div>
        <div className="lg:col-span-1">
          <ActivityFeed activities={activities} />
        </div>
      </div>
    </div>
  );
}
