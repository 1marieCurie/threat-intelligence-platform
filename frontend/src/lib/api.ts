import type {
  AlertDetail,
  AlertListResponse,
} from "../types/alert";

import type {
  DashboardSummary,
} from "../types/dashboard";

import type {
  InventoryImportResult,
  MachineInventoryPayload,
} from "../types/inventory";

import type {
  MachineDetail,
  MachineListResponse,
} from "../types/machine";

import type {
  SoftwareListResponse,
} from "../types/software";

import type {
  URLAnalysisResult,
} from "../types/urlAnalysis";

import type {
  VulnerabilityDetail,
  VulnerabilityListResponse,
} from "../types/vulnerability";


const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL
  ?? "http://127.0.0.1:8000";


const DEV_ORGANIZATION_ID =
  import.meta.env
    .VITE_DEV_ORGANIZATION_ID;


type ApiErrorPayload = {
  detail?: string;
};


async function readApiError(
  response: Response,
  fallback: string,
): Promise<string> {
  try {
    const payload: ApiErrorPayload =
      await response.json();

    if (
      typeof payload.detail === "string"
      && payload.detail.trim()
    ) {
      return payload.detail;
    }
  } catch {
    // Réponse non JSON :
    // conserver le message générique.
  }

  return fallback;
}


function requireDevelopmentOrganization(
): string {
  if (!DEV_ORGANIZATION_ID) {
    throw new Error(
      "L'organisation de développement "
      + "n'est pas configurée.",
    );
  }

  return DEV_ORGANIZATION_ID;
}


export async function analyzeURL(
  url: string,
): Promise<URLAnalysisResult> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/url-analysis`,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",
      },

      body: JSON.stringify({
        url,
      }),
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible d'analyser cette URL.",
      );

    throw new Error(
      message,
    );
  }

  const payload: URLAnalysisResult =
    await response.json();

  return payload;
}


export async function getDashboard(
): Promise<DashboardSummary> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/dashboard`,
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible de charger le dashboard.",
      );

    throw new Error(
      message,
    );
  }

  const payload: DashboardSummary =
    await response.json();

  return payload;
}


export async function getMachines(
): Promise<MachineListResponse> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/machines`,
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible de charger les machines.",
      );

    throw new Error(
      message,
    );
  }

  const payload: MachineListResponse =
    await response.json();

  return payload;
}


export async function getMachineDetail(
  machineId: string,
): Promise<MachineDetail> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    (
      `${API_BASE_URL}`
      + "/api/v1/machines/"
      + encodeURIComponent(
        machineId,
      )
    ),
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    if (
      response.status === 404
    ) {
      throw new Error(
        "Machine introuvable.",
      );
    }

    const message =
      await readApiError(
        response,
        "Impossible de charger cette machine.",
      );

    throw new Error(
      message,
    );
  }

  const payload: MachineDetail =
    await response.json();

  return payload;
}


export async function getSoftware(
): Promise<SoftwareListResponse> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/software`,
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible de charger les logiciels.",
      );

    throw new Error(
      message,
    );
  }

  const payload: SoftwareListResponse =
    await response.json();

  return payload;
}


export async function getVulnerabilities(
): Promise<VulnerabilityListResponse> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/vulnerabilities`,
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible de charger les vulnérabilités.",
      );

    throw new Error(
      message,
    );
  }

  const payload: VulnerabilityListResponse =
    await response.json();

  return payload;
}


export async function getVulnerabilityDetail(
  vulnerabilityId: string,
): Promise<VulnerabilityDetail> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    (
      `${API_BASE_URL}`
      + "/api/v1/vulnerabilities/"
      + encodeURIComponent(
        vulnerabilityId,
      )
    ),
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    if (
      response.status === 404
    ) {
      throw new Error(
        "Vulnérabilité introuvable.",
      );
    }

    const message =
      await readApiError(
        response,
        "Impossible de charger cette vulnérabilité.",
      );

    throw new Error(
      message,
    );
  }

  const payload: VulnerabilityDetail =
    await response.json();

  return payload;
}


export async function getAlerts(
): Promise<AlertListResponse> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/alerts`,
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible de charger les alertes.",
      );

    throw new Error(
      message,
    );
  }

  const payload: AlertListResponse =
    await response.json();

  return payload;
}


export async function getAlertDetail(
  alertId: string,
): Promise<AlertDetail> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    (
      `${API_BASE_URL}`
      + "/api/v1/alerts/"
      + encodeURIComponent(
        alertId,
      )
    ),
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          organizationId,
      },
    },
  );

  if (!response.ok) {
    if (
      response.status === 404
    ) {
      throw new Error(
        "Alerte introuvable.",
      );
    }

    const message =
      await readApiError(
        response,
        "Impossible de charger cette alerte.",
      );

    throw new Error(
      message,
    );
  }

  const payload: AlertDetail =
    await response.json();

  return payload;
}


export async function getWindowsInventoryScript(
): Promise<string> {
  const response = await fetch(
    (
      `${API_BASE_URL}`
      + "/api/v1/inventory-agent/windows/script"
    ),
    {
      method: "GET",
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible de charger le script Windows.",
      );

    throw new Error(
      message,
    );
  }

  return response.text();
}


export async function importInventory(
  inventory: MachineInventoryPayload,
): Promise<InventoryImportResult> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    (
      `${API_BASE_URL}`
      + "/api/v1/inventory-imports"
    ),
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",

        "X-Organization-Id":
          organizationId,
      },

      body: JSON.stringify(
        inventory,
      ),
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible d'importer cet inventaire.",
      );

    throw new Error(
      message,
    );
  }

  const payload: InventoryImportResult =
    await response.json();

  return payload;
}