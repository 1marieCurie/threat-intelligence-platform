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