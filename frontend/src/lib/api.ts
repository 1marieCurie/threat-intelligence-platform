import type {
  URLAnalysisResult,
} from "../types/urlAnalysis";


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