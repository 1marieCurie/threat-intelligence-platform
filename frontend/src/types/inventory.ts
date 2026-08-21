export interface InventoryAgent {
  name: string;
  version: string;
}


export interface InventoryMachine {
  machine_uid: string;
  hostname: string;
  os_name: string;
  os_version: string;
  architecture: string;
}


export interface InventoryApplicationComponent {
  component_type: "application";
  name: string;
  version: string | null;
  vendor: string | null;
  external_id: string;
  detected_by:
    "windows_registry_uninstall";
}


export interface InventoryPackageComponent {
  component_type: "package";
  ecosystem:
    | "pypi"
    | "npm";
  package_name: string;
  version: string;
  scope: "global";
  detected_by:
    | "pip_global"
    | "npm_global";
}


export type InventoryComponent =
  | InventoryApplicationComponent
  | InventoryPackageComponent;


export interface MachineInventoryPayload {
  schema_version: "inventory/v1";

  inventory_id: string;

  collected_at: string;

  agent: InventoryAgent;

  machine: InventoryMachine;

  components: InventoryComponent[];
}


export type InventoryImportStatus =
  | "imported"
  | "idempotent";


export interface InventoryImportResult {
  machine_id: string;

  inventory_id: string;

  status: InventoryImportStatus;

  machine_created: boolean;

  inserted_components: number;

  updated_components: number;

  deleted_components: number;

  component_count: number;
}