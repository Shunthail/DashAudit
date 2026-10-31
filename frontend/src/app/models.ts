export type Severity = "critical" | "high" | "medium" | "low";
export interface Finding {
  severity: Severity;
  title: string;
  detail: string;
  category: string;
}
export interface Audit {
  vulnerabilityCandidates?: { id: string; description: string; url: string }[];
  id: number;
  target: string;
  date: string;
  score: number;
  findings: Finding[];
  ports: { port: number; service: string }[];
  httpStatus: number | null;
  tls?: { valid: boolean; expiresAt?: string; protocol?: string };
  headers: Record<string, string>;
  address: string;
  vulnerabilityNote: string;
}
