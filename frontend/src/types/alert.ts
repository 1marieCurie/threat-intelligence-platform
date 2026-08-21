export type AlertType =
  | "new_confirmed_critical_exposure"
  | "confirmed_exposure_entered_kev"
  | "priority_transition_to_critical";


export type AlertStatus =
  | "pending"
  | "sent"
  | "failed";


export type AlertApplicabilityStatus =
  | "confirmed"
  | "potential";


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


export interface AlertIdentifier {
  namespace: string;
  value: string;
  is_primary: boolean;
}


export interface AlertWeakness {
  cwe_id: string;
  name: string;
  description: string;
}


export interface AlertRecipient {
  user_id: string;
  email: string;
  display_name: string;
}


export interface AlertMachine {
  machine_id: string;

  hostname: string;
  os_name: string;
  os_version: string;
  architecture: string;
}


export interface AlertComponent {
  component_id: string;

  component_type: string;
  name: string;

  version:
    | string
    | null;

  vendor:
    | string
    | null;

  ecosystem:
    | string
    | null;

  scope:
    | string
    | null;
}


export interface AlertExposure {
  exposure_id: string;

  applicability_status:
    AlertApplicabilityStatus;

  severity:
    | string
    | null;

  priority:
    | string
    | null;

  is_kev: boolean;

  match_rule: string;

  match_version:
    | string
    | null;

  first_detected_at: string;
  last_evaluated_at: string;
}


export interface AlertDetail {
  alert_id: string;

  alert_type: AlertType;
  status: AlertStatus;

  created_at: string;

  sent_at:
    | string
    | null;

  recipient: AlertRecipient;

  machine: AlertMachine;

  canonical_vulnerability_id: string;

  primary_identifier:
    | string
    | null;

  identifiers: AlertIdentifier[];

  component:
    | AlertComponent
    | null;

  exposure:
    | AlertExposure
    | null;

  epss_score:
    | number
    | null;

  epss_percentile:
    | number
    | null;

  cvss_score:
    | number
    | null;

  cvss_version:
    | string
    | null;

  cvss_vector:
    | string
    | null;

  cvss_source_name:
    | string
    | null;

  cvss_source_role:
    | string
    | null;

  weaknesses: AlertWeakness[];
}