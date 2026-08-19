import type {
  URLAnalysisResult,
} from "../types/urlAnalysis";

import type {
  DashboardSummary,
} from "../types/dashboard";

import type {
  MachineListResponse,
} from "../types/machine";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ??
  "http://127.0.0.1:8000";


type ApiErrorPayload = {
  detail?: string;
};


export async function analyzeURL(
  url: string,
): Promise<URLAnalysisResult> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/url-analysis`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
      }),
    },
  );

  if (!response.ok) {
    let message =
      "Impossible d'analyser cette URL.";

    try {
      const payload =
        (await response.json()) as ApiErrorPayload;

      if (
        typeof payload.detail === "string"
        && payload.detail.trim()
      ) {
        message = payload.detail;
      }
    } catch {
      // Réponse non JSON :
      // on conserve le message générique.
    }

    throw new Error(message);
  }

  return (
    await response.json()
  ) as URLAnalysisResult;
}

const DEV_ORGANIZATION_ID =
  import.meta.env
    .VITE_DEV_ORGANIZATION_ID;


export async function getDashboard(
): Promise<DashboardSummary> {
  if (!DEV_ORGANIZATION_ID) {
    throw new Error(
      "L'organisation de développement "
      + "n'est pas configurée.",
    );
  }

  const response = await fetch(
    `${API_BASE_URL}/api/v1/dashboard`,
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          DEV_ORGANIZATION_ID,
      },
    },
  );

  if (!response.ok) {
    let message =
      "Impossible de charger le dashboard.";

    try {
      const payload =
        (await response.json()) as {
          detail?: string;
        };

      if (
        typeof payload.detail
          === "string"
        && payload.detail.trim()
      ) {
        message =
          payload.detail;
      }
    } catch {
      // Réponse non JSON :
      // on conserve le message générique.
    }

    throw new Error(
      message,
    );
  }

  return (
    await response.json()
  ) as DashboardSummary;
}

export async function getMachines(
): Promise<MachineListResponse> {
  if (!DEV_ORGANIZATION_ID) {
    throw new Error(
      "L'organisation de développement "
      + "n'est pas configurée.",
    );
  }

  const response = await fetch(
    `${API_BASE_URL}/api/v1/machines`,
    {
      method: "GET",

      headers: {
        "X-Organization-Id":
          DEV_ORGANIZATION_ID,
      },
    },
  );

  if (!response.ok) {
    let message =
      "Impossible de charger les machines.";

    try {
      const payload =
        (await response.json()) as {
          detail?: string;
        };

      if (
        typeof payload.detail
          === "string"
        && payload.detail.trim()
      ) {
        message =
          payload.detail;
      }
    } catch {
      // Réponse non JSON :
      // message générique conservé.
    }

    throw new Error(
      message,
    );
  }

  return (
    await response.json()
  ) as MachineListResponse;
}