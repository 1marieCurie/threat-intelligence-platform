export type DashboardPriority =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type DashboardAlertStatus =
  | "pending"
  | "sent"
  | "failed";


export interface PriorityDistribution {
  low: number;
  medium: number;
  high: number;
  critical: number;
}


export interface TopMachine {
  machine_id: string;
  hostname: string;
  exposure_count: number;
  critical_count: number;
  kev_count: number;
}


export interface PriorityAction {
  kind:
    | "critical_confirmed"
    | "confirmed_kev"
    | "notification_attention";

  title: string;
  count: number;
  priority: DashboardPriority;
}


export interface LatestAlert {
  alert_id: string;
  alert_type: string;

  status: DashboardAlertStatus;

  created_at: string;
  sent_at: string | null;

  machine_id: string;
  hostname: string;

  priority:
    | DashboardPriority
    | null;
}


export interface DashboardSummary {
  machine_count: number;
  component_count: number;

  confirmed_exposure_count: number;
  potential_exposure_count: number;

  critical_exposure_count: number;
  kev_exposure_count: number;

  pending_alert_count: number;
  failed_alert_count: number;

  priority_distribution:
    PriorityDistribution;

  top_machines:
    TopMachine[];

  priority_actions:
    PriorityAction[];

  latest_alerts:
    LatestAlert[];
}