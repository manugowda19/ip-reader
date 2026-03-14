"use client";

import { ShieldAlert, ArrowUpRight, TrendingUp, TrendingDown } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

export interface TopIP {
  ip: string;
  score: number;
}

interface MaliciousIPsTableProps {
  ips: TopIP[];
  onSelectIP?: (ip: string) => void;
}

export function MaliciousIPsTable({ ips, onSelectIP }: MaliciousIPsTableProps) {
  const getThreatBadge = (score: number) => {
    if (score >= 80) {
      return <Badge className="bg-danger/15 text-danger border-danger/30 font-mono">Critical</Badge>;
    } else if (score >= 60) {
      return <Badge className="bg-warning/15 text-warning border-warning/30 font-mono">High</Badge>;
    }
    return <Badge className="bg-primary/15 text-primary border-primary/30 font-mono">Medium</Badge>;
  };

  const getTrendIcon = (trend: "up" | "down" | "stable") => {
    switch (trend) {
      case "up":
        return <TrendingUp className="h-4 w-4 text-danger" />;
      case "down":
        return <TrendingDown className="h-4 w-4 text-success" />;
      default:
        return <div className="h-4 w-4 flex items-center justify-center text-muted-foreground">—</div>;
    }
  };

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-danger" />
            <CardTitle className="text-lg font-semibold text-card-foreground">Top Malicious IPs</CardTitle>
          </div>
          <Badge variant="outline" className="text-muted-foreground">
            Last 24 hours
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[320px] px-1 pb-4">
          <div className="rounded-md border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-secondary/50 hover:bg-secondary/50 border-border">
                  <TableHead className="text-muted-foreground font-medium">IP Address</TableHead>
                  <TableHead className="text-muted-foreground font-medium">Score</TableHead>
                  <TableHead className="text-muted-foreground font-medium hidden sm:table-cell">Severity</TableHead>
                  <TableHead className="text-muted-foreground font-medium text-center">Trend</TableHead>
                  <TableHead className="text-muted-foreground font-medium w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ips.map((ip, index) => (
                  <TableRow
                    key={index}
                    className="border-border hover:bg-secondary/30 cursor-pointer transition-colors"
                    onClick={() => onSelectIP?.(ip.ip)}
                  >
                    <TableCell className="font-mono text-foreground font-medium">{ip.ip}</TableCell>
                    <TableCell>
                      <span
                        className={`font-mono font-bold ${
                          ip.score >= 80
                            ? "text-danger"
                            : ip.score >= 60
                            ? "text-warning"
                            : "text-primary"
                        }`}
                      >
                        {ip.score}
                      </span>
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      {getThreatBadge(ip.score)}
                    </TableCell>
                    <TableCell className="text-center">{getTrendIcon("stable")}</TableCell>
                    <TableCell>
                      <ArrowUpRight className="h-4 w-4 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
