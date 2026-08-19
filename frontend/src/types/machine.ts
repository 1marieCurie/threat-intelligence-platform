export interface MachineSummary {
  machine_id: string;

  hostname: string;

  os_name: string;
  os_version: string;
  architecture: string;

  last_inventory_at:
    | string
    | null;

  component_count: number;

  exposure_count: number;

  critical_exposure_count: number;

  kev_exposure_count: number;
}


export interface MachineListResponse {
  items: MachineSummary[];
}


export interface MachineComponent {
  component_id: string;

  component_type:
    | "application"
    | "package";

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

  detected_by: string;
}


export interface MachineExposure {
  exposure_id: string;

  canonical_vulnerability_id: string;

  primary_identifier:
    | string
    | null;

  component_id: string;

  component_name: string;

  component_version:
    | string
    | null;

  applicability_status:
    | "confirmed"
    | "potential";

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
}


export interface MachineDetail {
  machine_id: string;
  machine_uid: string;

  hostname: string;

  os_name: string;
  os_version: string;
  architecture: string;

  last_inventory_at:
    | string
    | null;

  components: MachineComponent[];

  exposures: MachineExposure[];
}