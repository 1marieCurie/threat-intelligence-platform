import type {
  AlertDetail,
  AlertListResponse,
} from "../types/alert";

import type {
  AuthTokenResponse,
  AuthUser,
} from "../types/auth";

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


type AuthenticationListener = (
  user: AuthUser | null,
) => void;


let accessToken:
  string | null = null;


let authenticationListener:
  AuthenticationListener | null = null;


let bootstrapPromise:
  Promise<AuthUser | null>
  | null = null;


export function setAuthenticationListener(
  listener: AuthenticationListener | null,
): void {
  authenticationListener =
    listener;
}


function updateAuthentication(
  token: string | null,
  user: AuthUser | null,
): void {
  accessToken = token;

  authenticationListener?.(
    user,
  );
}


async function readApiError(
  response: Response,
  fallback: string,
): Promise<string> {
  try {
    const payload: ApiErrorPayload =
      await response.json();

    if (
      typeof payload.detail
        === "string"
      && payload.detail.trim()
    ) {
      return payload.detail;
    }
  } catch {
    // Réponse non JSON.
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


function authorizationHeaders(
  headers?: HeadersInit,
): Headers {
  const result =
    new Headers(
      headers,
    );

  if (accessToken) {
    result.set(
      "Authorization",
      `Bearer ${accessToken}`,
    );
  }

  return result;
}


async function rawRefresh(
): Promise<AuthTokenResponse> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/auth/refresh`,
    {
      method: "POST",

      credentials:
        "include",
    },
  );

  if (!response.ok) {
    updateAuthentication(
      null,
      null,
    );

    const message =
      await readApiError(
        response,
        "Votre session a expiré.",
      );

    throw new Error(
      message,
    );
  }

  const payload:
    AuthTokenResponse =
      await response.json();

  updateAuthentication(
    payload.access_token,
    payload.user,
  );

  return payload;
}


async function authenticatedFetch(
  path: string,
  init: RequestInit = {},
  retryOnUnauthorized = true,
): Promise<Response> {
  if (!accessToken) {
    throw new Error(
      "Authentification requise.",
    );
  }

  const response = await fetch(
    `${API_BASE_URL}${path}`,
    {
      ...init,

      credentials:
        "include",

      headers:
        authorizationHeaders(
          init.headers,
        ),
    },
  );

  if (
    response.status === 401
    && retryOnUnauthorized
  ) {
    await rawRefresh();

    return authenticatedFetch(
      path,
      init,
      false,
    );
  }

  return response;
}


export async function login(
  email: string,
  password: string,
): Promise<AuthTokenResponse> {
  const organizationId =
    requireDevelopmentOrganization();

  const response = await fetch(
    `${API_BASE_URL}/api/v1/auth/login`,
    {
      method: "POST",

      credentials:
        "include",

      headers: {
        "Content-Type":
          "application/json",
      },

      body: JSON.stringify({
        organization_id:
          organizationId,

        email,
        password,
      }),
    },
  );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Connexion impossible.",
      );

    throw new Error(
      message,
    );
  }

  const payload:
    AuthTokenResponse =
      await response.json();

  updateAuthentication(
    payload.access_token,
    payload.user,
  );

  return payload;
}


export async function refreshAuthentication(
): Promise<AuthTokenResponse> {
  return rawRefresh();
}


export async function getCurrentUser(
): Promise<AuthUser> {
  const response =
    await authenticatedFetch(
      "/api/v1/auth/me",
      {
        method: "GET",
      },
    );

  if (!response.ok) {
    const message =
      await readApiError(
        response,
        "Impossible de vérifier la session.",
      );

    throw new Error(
      message,
    );
  }

  const user: AuthUser =
    await response.json();

  authenticationListener?.(
    user,
  );

  return user;
}


export function bootstrapAuthentication(
): Promise<AuthUser | null> {
  if (bootstrapPromise) {
    return bootstrapPromise;
  }

  bootstrapPromise = (
    async () => {
      try {
        await rawRefresh();

        return await getCurrentUser();
      } catch {
        updateAuthentication(
          null,
          null,
        );

        return null;
      }
    }
  )();

  return bootstrapPromise;
}


export async function logout(
): Promise<void> {
  try {
    if (accessToken) {
      await authenticatedFetch(
        "/api/v1/auth/logout",
        {
          method: "POST",
        },
        false,
      );
    }
  } finally {
    updateAuthentication(
      null,
      null,
    );
  }
}


export async function analyzeURL(
  url: string,
): Promise<URLAnalysisResult> {
  const response =
    await authenticatedFetch(
      "/api/v1/url-analysis",
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

  const payload:
    URLAnalysisResult =
      await response.json();

  return payload;
}


export async function getDashboard(
): Promise<DashboardSummary> {
  const response =
    await authenticatedFetch(
      "/api/v1/dashboard",
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

  return response.json();
}


export async function getMachines(
): Promise<MachineListResponse> {
  const response =
    await authenticatedFetch(
      "/api/v1/machines",
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

  return response.json();
}


export async function getMachineDetail(
  machineId: string,
): Promise<MachineDetail> {
  const response =
    await authenticatedFetch(
      (
        "/api/v1/machines/"
        + encodeURIComponent(
          machineId,
        )
      ),
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

  return response.json();
}


export async function getSoftware(
): Promise<SoftwareListResponse> {
  const response =
    await authenticatedFetch(
      "/api/v1/software",
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

  return response.json();
}


export async function getVulnerabilities(
): Promise<VulnerabilityListResponse> {
  const response =
    await authenticatedFetch(
      "/api/v1/vulnerabilities",
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

  return response.json();
}


export async function getVulnerabilityDetail(
  vulnerabilityId: string,
): Promise<VulnerabilityDetail> {
  const response =
    await authenticatedFetch(
      (
        "/api/v1/vulnerabilities/"
        + encodeURIComponent(
          vulnerabilityId,
        )
      ),
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

  return response.json();
}


export async function getAlerts(
): Promise<AlertListResponse> {
  const response =
    await authenticatedFetch(
      "/api/v1/alerts",
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

  return response.json();
}


export async function getAlertDetail(
  alertId: string,
): Promise<AlertDetail> {
  const response =
    await authenticatedFetch(
      (
        "/api/v1/alerts/"
        + encodeURIComponent(
          alertId,
        )
      ),
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

  return response.json();
}


export async function getWindowsInventoryScript(
): Promise<string> {
  const response =
    await authenticatedFetch(
      (
        "/api/v1/"
        + "inventory-agent/windows/script"
      ),
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
  const response =
    await authenticatedFetch(
      "/api/v1/inventory-imports",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
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

  return response.json();
}