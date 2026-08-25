import type {
  URLAnalysisResult,
} from "../types/urlAnalysis";


const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL
  ?? "http://127.0.0.1:8000";


type ApiErrorPayload = {
  detail?: unknown;
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
    // Réponse non JSON.
  }

  return fallback;
}


export async function analyzePublicURL(
  url: string,
): Promise<URLAnalysisResult> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/public/url-analysis`,
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
    const message = await readApiError(
      response,
      "Impossible d'analyser cette URL.",
    );

    throw new Error(message);
  }

  return response.json();
}
