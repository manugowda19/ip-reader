"use client";

import Link from "next/link";
import { Shield, Settings, Activity } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";

export function DashboardHeader() {
  const { theme, systemTheme, setTheme } = useTheme();
  const resolvedTheme =
    theme === "system" || !theme ? systemTheme ?? "light" : theme;
  const currentTheme = resolvedTheme === "dark" ? "dark" : "light";
  const nextTheme = currentTheme === "dark" ? "light" : "dark";

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between">
          {/* Logo and Brand */}
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-primary/15">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div className="flex flex-col">
              <span className="text-lg font-bold text-foreground tracking-tight">ThreatGuard</span>
              <span className="text-[10px] text-muted-foreground -mt-0.5 uppercase tracking-wider">Intelligence Platform</span>
            </div>
          </div>

          {/* Center Nav - Hidden on mobile */}
          <nav className="hidden md:flex items-center gap-1">
            <Button variant="ghost" size="sm" className="text-foreground" asChild>
              <Link href="/">Dashboard</Link>
            </Button>
            <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-foreground" asChild>
              <Link href="/admin">Admin</Link>
            </Button>
          </nav>

          {/* Right Section */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Live Status */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-success/10 border border-success/20">
              <Activity className="h-3.5 w-3.5 text-success animate-pulse" />
              <span className="text-xs font-medium text-success">Live</span>
            </div>

            {/* Theme Settings */}
            <Button
              variant="ghost"
              size="sm"
              className="hidden sm:inline-flex items-center gap-2 px-3"
              onClick={() => setTheme(nextTheme)}
            >
              <Settings className="h-4 w-4 text-muted-foreground" />
              <span className="text-xs font-medium text-muted-foreground">
                Theme: {currentTheme === "light" ? "Light" : "Dark"}
              </span>
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}
