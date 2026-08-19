export type URLVerdict =
  | "benign"
  | "malicious";

export type URLThreatClass =
  | "benign"
  | "phishing"
  | "malware";

export interface URLAnalysisResult {
  verdict: URLVerdict;
  threat_class: URLThreatClass;
  confidence: number;
  model_version: string;
}

export type UserRole =
  | "staff"
  | "security_responsible";