export interface SoftwareSummary {
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

  machine_count: number;

  exposure_count: number;
}


export interface SoftwareListResponse {
  items: SoftwareSummary[];
}