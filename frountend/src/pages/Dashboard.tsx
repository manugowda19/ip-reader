import { useState } from "react";
import { DashboardHeader } from "@/components/dashboard-header";
import { IPSearch } from "@/components/ip-search";
import { IPResultPanel, type IPResult, type GeoInfo, type WhoisInfo } from "@/components/ip-result-panel";

type BackendLookup =
  | {
      ip: string;
      malicious: true;
      score: number;
      source_count: number;
      sources: string[];
      first_seen?: string | null;
      last_seen?: string | null;
    }
  | {
      ip: string;
      malicious: false;
      message?: string;
    };

export default function ThreatIntelligenceDashboard() {
  const [searchResult, setSearchResult] = useState<IPResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleIPSearch = async (ip: string) => {
    setIsLoading(true);
    try {
      const [lookupRes, whoisRes] = await Promise.all([
        fetch(`/api/ip/${encodeURIComponent(ip)}`),
        fetch(`/api/whois/${encodeURIComponent(ip)}`),
      ]);

      if (!lookupRes.ok) throw new Error("lookup failed");
      const data = (await lookupRes.json()) as BackendLookup;

      let geo: GeoInfo | null = null;
      let whois: WhoisInfo | null = null;
      if (whoisRes.ok) {
        const whoisData = await whoisRes.json();
        geo = whoisData.geo ?? null;
        whois = whoisData.whois ?? null;
      }

      const result: IPResult = data.malicious
        ? {
            ipAddress: data.ip,
            threatScore: data.score,
            verdict: data.score >= 70 ? "malicious" : "suspicious",
            lastAnalyzed: "Just now",
            sources: (data.sources ?? []).map((name) => ({ name, reported: true })),
            geo,
            whois,
          }
        : {
            ipAddress: data.ip,
            threatScore: 0,
            verdict: "clean",
            lastAnalyzed: "Just now",
            sources: [
              {
                name: data.message?.trim() ? `Threat DB: ${data.message}` : "Threat DB: not found",
                reported: false,
              },
            ],
            geo,
            whois,
          };

      setSearchResult(result);
    } catch {
      setSearchResult({
        ipAddress: ip,
        threatScore: 0,
        verdict: "clean",
        lastAnalyzed: "Just now",
        sources: [{ name: "Backend unreachable", reported: false }],
      });
    }
    setIsLoading(false);
  };

  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />

      <main className="container mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold text-foreground">Threat Intelligence Dashboard</h1>
          <p className="text-sm text-muted-foreground">IP Details</p>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold text-foreground">IP Reputation Check</h2>
          </div>
          <IPSearch onSearch={handleIPSearch} isLoading={isLoading} />
        </div>

        <IPResultPanel result={searchResult} />
      </main>
    </div>
  );
}
