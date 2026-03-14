"use client";

import { useState } from "react";
import { Search, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface IPSearchProps {
  onSearch: (ip: string) => void | Promise<void>;
  isLoading?: boolean;
}

export function IPSearch({ onSearch, isLoading }: IPSearchProps) {
  const [ipAddress, setIpAddress] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (ipAddress.trim()) {
      await onSearch(ipAddress.trim());
    }
  };

  const isValidIP = (ip: string) => {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip) || ip === "";
  };

  return (
    <form onSubmit={handleSubmit} className="flex gap-3">
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          type="text"
          placeholder="Enter IP address to check reputation (e.g., 192.168.1.1)"
          value={ipAddress}
          onChange={(e) => setIpAddress(e.target.value)}
          className="pl-10 bg-secondary border-border h-11 font-mono text-sm placeholder:font-sans placeholder:text-muted-foreground"
        />
      </div>
      <Button
        type="submit"
        disabled={!ipAddress.trim() || !isValidIP(ipAddress) || isLoading}
        className="bg-primary text-primary-foreground hover:bg-primary/90 h-11 px-6"
      >
        {isLoading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Analyzing
          </>
        ) : (
          "Check IP"
        )}
      </Button>
    </form>
  );
}
