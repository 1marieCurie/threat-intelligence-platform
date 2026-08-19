import type {
  DashboardSummary,
} from "../types/dashboard";

import type {
  MachineDetail,
  MachineListResponse,
} from "../types/machine";

import type {
  URLAnalysisResult,
} from "../types/urlAnalysis";


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
    // Si la réponse n'est pas du JSON,
    // on conserve le message générique.
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
      + `/api/v1/machines/${machineId}`
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
    if (response.status === 404) {
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