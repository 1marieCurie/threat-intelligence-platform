export type AlertType =
  | "new_confirmed_critical_exposure"
  | "confirmed_exposure_entered_kev"
  | "priority_transition_to_critical";


export type AlertStatus =
  | "pending"
  | "sent"
  | "failed";


export interface AlertSummary {
  alert_id: string;

  alert_type: AlertType;
  status: AlertStatus;

  created_at: string;
  sent_at:
    | string
    | null;

  machine_id: string;
  machine_hostname: string;

  canonical_vulnerability_id: string;
  primary_identifier:
    | string
    | null;

  component_name:
    | string
    | null;

  component_version:
    | string
    | null;

  current_priority:
    | string
    | null;

  is_kev:
    | boolean
    | null;
}


export interface AlertListResponse {
  items: AlertSummary[];
}