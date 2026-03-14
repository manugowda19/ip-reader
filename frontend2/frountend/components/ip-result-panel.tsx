"use client";

import { Shield, ShieldAlert, ShieldCheck, ShieldQuestion, Globe, Clock, Server, MapPin, Building2, Mail, Network } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

export interface GeoInfo {
  country?: string;
  country_code?: string;
  continent?: string;
  region?: string;
  city?: string;
  district?: string;
  zip?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  utc_offset?: number;
  currency?: string;
  isp?: string;
  org?: string;
  as_number?: string;
  as_name?: string;
  reverse_dns?: string;
  is_mobile?: boolean;
  is_proxy?: boolean;
  is_hosting?: boolean;
}

export interface WhoisInfo {
  name?: string;
  handle?: string;
  type?: string;
  start_address?: string;
  end_address?: string;
  country?: string;
  parent_handle?: string;
  cidr?: string;
  status?: string[];
  org_name?: string;
  address?: string;
  phone?: string;
  abuse_email?: string;
  abuse_phone?: string;
  tech_email?: string;
  registration_date?: string;
  last_changed?: string;
  remarks?: string;
}

export interface IPResult {
  ipAddress: string;
  threatScore: number;
  verdict: "malicious" | "suspicious" | "clean";
  sources: { name: string; reported: boolean; lastSeen?: string }[];
  country?: string;
  isp?: string;
  lastAnalyzed?: string;
  geo?: GeoInfo | null;
  whois?: WhoisInfo | null;
}

interface IPResultPanelProps {
  result: IPResult | null;
}

export function IPResultPanel({ result }: IPResultPanelProps) {
  if (!result) {
    return (
      <Card className="bg-card border-border">
        <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <ShieldQuestion className="h-16 w-16 mb-4 opacity-50" />
          <p className="text-lg font-medium">No IP analyzed</p>
          <p className="text-sm">Enter an IP address above to check its reputation</p>
        </CardContent>
      </Card>
    );
  }

  const getVerdictConfig = (verdict: IPResult["verdict"]) => {
    switch (verdict) {
      case "malicious":
        return {
          icon: ShieldAlert,
          label: "Malicious",
          bgColor: "bg-danger/10",
          textColor: "text-danger",
          borderColor: "border-danger/30",
          progressColor: "bg-danger",
        };
      case "suspicious":
        return {
          icon: Shield,
          label: "Suspicious",
          bgColor: "bg-warning/10",
          textColor: "text-warning",
          borderColor: "border-warning/30",
          progressColor: "bg-warning",
        };
      case "clean":
        return {
          icon: ShieldCheck,
          label: "Clean",
          bgColor: "bg-success/10",
          textColor: "text-success",
          borderColor: "border-success/30",
          progressColor: "bg-success",
        };
    }
  };

  const verdictConfig = getVerdictConfig(result.verdict);
  const VerdictIcon = verdictConfig.icon;

  return (
    <div className="space-y-4">
      <Card className="bg-card border-border">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg font-semibold text-card-foreground">Analysis Results</CardTitle>
            <Badge variant="outline" className={`${verdictConfig.bgColor} ${verdictConfig.textColor} ${verdictConfig.borderColor} font-medium`}>
              <VerdictIcon className="h-3.5 w-3.5 mr-1.5" />
              {verdictConfig.label}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* IP Address and Score */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Globe className="h-4 w-4" />
                <span>IP Address</span>
              </div>
              <p className="font-mono text-2xl font-bold text-foreground">{result.ipAddress}</p>
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                {result.geo?.country && <span>{result.geo.country}</span>}
                {result.geo?.isp && <span className="truncate">{result.geo.isp}</span>}
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Threat Score</span>
                <span className={`text-2xl font-bold ${verdictConfig.textColor}`}>{result.threatScore}/100</span>
              </div>
              <Progress value={result.threatScore} className="h-3 bg-secondary" />
              <p className="text-xs text-muted-foreground">
                {result.threatScore >= 70 ? "High risk - Immediate action recommended" :
                 result.threatScore >= 40 ? "Medium risk - Monitor closely" :
                 "Low risk - No immediate concerns"}
              </p>
            </div>
          </div>

          {/* Metadata */}
          {result.lastAnalyzed && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground border-t border-border pt-4">
              <Clock className="h-4 w-4" />
              <span>Last analyzed: {result.lastAnalyzed}</span>
            </div>
          )}

          {/* Sources */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm font-medium text-foreground">
              <Server className="h-4 w-4" />
              <span>Threat Intelligence Sources</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {result.sources.map((source, index) => (
                <div
                  key={index}
                  className={`flex items-center justify-between px-3 py-2 rounded-md border ${
                    source.reported
                      ? "bg-danger/5 border-danger/20"
                      : "bg-secondary border-border"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${source.reported ? "bg-danger" : "bg-success"}`} />
                    <span className="text-sm font-medium text-foreground">{source.name}</span>
                  </div>
                  <span className={`text-xs ${source.reported ? "text-danger" : "text-success"}`}>
                    {source.reported ? "Reported" : "Clean"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* WHOIS + Map - Two separate frames side by side */}
      {(result.geo || result.whois) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Frame 1: Full IP Details */}
          <Card className="bg-card border-border overflow-auto max-h-[500px]">
            <CardHeader className="pb-3 sticky top-0 bg-card z-10">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Network className="h-4 w-4" />
                IP Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2.5 text-sm">
                {/* Ownership */}
                {result.whois?.org_name && (
                  <Row label="Organization" value={result.whois.org_name} />
                )}
                {result.whois?.name && (
                  <Row label="Network Name" value={result.whois.name} />
                )}
                {result.whois?.handle && (
                  <Row label="Handle" value={result.whois.handle} mono />
                )}
                {result.whois?.parent_handle && (
                  <Row label="Parent Handle" value={result.whois.parent_handle} mono />
                )}
                {(result.whois?.start_address && result.whois?.end_address) && (
                  <Row label="IP Range" value={`${result.whois.start_address} — ${result.whois.end_address}`} mono />
                )}
                {result.whois?.cidr && (
                  <Row label="CIDR" value={result.whois.cidr} mono />
                )}
                {result.whois?.type && (
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Type</span>
                    <Badge variant="secondary" className="text-xs">{result.whois.type}</Badge>
                  </div>
                )}
                {result.whois?.address && (
                  <Row label="Address" value={result.whois.address} />
                )}
                {result.whois?.phone && (
                  <Row label="Phone" value={result.whois.phone} />
                )}
                {result.whois?.registration_date && (
                  <Row label="Registered" value={new Date(result.whois.registration_date).toLocaleDateString()} />
                )}
                {result.whois?.last_changed && (
                  <Row label="Last Changed" value={new Date(result.whois.last_changed).toLocaleDateString()} />
                )}

                {/* Abuse & Tech Contacts */}
                {(result.whois?.abuse_email || result.whois?.abuse_phone || result.whois?.tech_email) && (
                  <>
                    <div className="border-t border-border my-1" />
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Contacts</p>
                  </>
                )}
                {result.whois?.abuse_email && (
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground flex items-center gap-1">
                      <Mail className="h-3.5 w-3.5" /> Abuse Email
                    </span>
                    <span className="text-foreground font-medium text-xs">{result.whois.abuse_email}</span>
                  </div>
                )}
                {result.whois?.abuse_phone && (
                  <Row label="Abuse Phone" value={result.whois.abuse_phone} />
                )}
                {result.whois?.tech_email && (
                  <Row label="Tech Email" value={result.whois.tech_email} />
                )}

                {/* Geolocation */}
                {result.geo && (
                  <>
                    <div className="border-t border-border my-1" />
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Geolocation</p>
                  </>
                )}
                {result.geo?.city && (
                  <Row label="Location" value={[result.geo.city, result.geo.district, result.geo.region, result.geo.country].filter(Boolean).join(", ")} />
                )}
                {result.geo?.continent && (
                  <Row label="Continent" value={result.geo.continent} />
                )}
                {result.geo?.country_code && (
                  <Row label="Country Code" value={result.geo.country_code} />
                )}
                {result.geo?.zip && (
                  <Row label="ZIP Code" value={result.geo.zip} />
                )}
                {(result.geo?.lat !== undefined && result.geo?.lon !== undefined) && (
                  <Row label="Coordinates" value={`${result.geo.lat}, ${result.geo.lon}`} mono />
                )}
                {result.geo?.timezone && (
                  <Row label="Timezone" value={result.geo.timezone} />
                )}
                {result.geo?.currency && (
                  <Row label="Currency" value={result.geo.currency} />
                )}

                {/* Network */}
                {result.geo && (
                  <>
                    <div className="border-t border-border my-1" />
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Network</p>
                  </>
                )}
                {result.geo?.isp && (
                  <Row label="ISP" value={result.geo.isp} />
                )}
                {result.geo?.org && (
                  <Row label="Organization" value={result.geo.org} />
                )}
                {result.geo?.as_number && (
                  <Row label="ASN" value={result.geo.as_number} mono />
                )}
                {result.geo?.as_name && (
                  <Row label="AS Name" value={result.geo.as_name} />
                )}
                {result.geo?.reverse_dns && (
                  <Row label="Reverse DNS" value={result.geo.reverse_dns} mono />
                )}

                {/* Flags */}
                {(result.geo?.is_mobile || result.geo?.is_proxy || result.geo?.is_hosting) && (
                  <>
                    <div className="border-t border-border my-1" />
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Flags</p>
                    <div className="flex flex-wrap gap-2">
                      {result.geo.is_mobile && <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-400 border-blue-500/30">Mobile</Badge>}
                      {result.geo.is_proxy && <Badge variant="outline" className="text-xs bg-orange-500/10 text-orange-400 border-orange-500/30">Proxy / VPN</Badge>}
                      {result.geo.is_hosting && <Badge variant="outline" className="text-xs bg-purple-500/10 text-purple-400 border-purple-500/30">Hosting / Datacenter</Badge>}
                    </div>
                  </>
                )}

                {/* Remarks */}
                {result.whois?.remarks && (
                  <>
                    <div className="border-t border-border my-1" />
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Remarks</p>
                    <p className="text-xs text-muted-foreground leading-relaxed">{result.whois.remarks}</p>
                  </>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Frame 2: Google Maps Only */}
          {result.geo?.lat !== undefined && result.geo?.lon !== undefined && (
            <Card className="bg-card border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base font-semibold flex items-center gap-2">
                  <MapPin className="h-4 w-4" />
                  IP Location Map
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0 overflow-hidden rounded-b-lg">
                <iframe
                  width="100%"
                  height="380"
                  style={{ border: 0 }}
                  loading="lazy"
                  referrerPolicy="no-referrer-when-downgrade"
                  src={`https://www.google.com/maps?q=${result.geo.lat},${result.geo.lon}&z=10&output=embed`}
                  title={`Map location of ${result.ipAddress}`}
                />
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className={`text-foreground font-medium text-right truncate ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </span>
    </div>
  );
}
