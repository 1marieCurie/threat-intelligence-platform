import {
  useState,
} from "react";

import type {
  FormEvent,
} from "react";

import {
  analyzeURL,
} from "../../lib/api";

import {
  Badge,
} from "../../components/ui/Badge";

import {
  Button,
} from "../../components/ui/Button";

import {
  Card,
} from "../../components/ui/Card";

import {
  Input,
} from "../../components/ui/Input";

import type {
  URLAnalysisResult,
} from "../../types/urlAnalysis";


export function URLAnalysisPage() {
  const [url, setUrl] =
    useState("");

  const [result, setResult] =
    useState<URLAnalysisResult | null>(
      null,
    );

  const [error, setError] =
    useState<string | null>(
      null,
    );

  const [isLoading, setIsLoading] =
    useState(false);


  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    const value = url.trim();

    if (!value) {
      setResult(null);
      setError(
        "Veuillez saisir une URL.",
      );
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const analysis =
        await analyzeURL(value);

      setResult(analysis);
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Une erreur inattendue est survenue.",
      );
    } finally {
      setIsLoading(false);
    }
  }


  return (
    <main className="url-analysis">
      <header className="page-header">
        <span className="eyebrow">
          Analyse temps réel
        </span>

        <h1>
          Analyse d'URL
        </h1>

        <p>
          Analysez une adresse web avec
          le moteur de classification de
          menaces de la plateforme.
        </p>
      </header>

      <Card>
        <form
          onSubmit={handleSubmit}
          className="analysis-form"
        >
          <label
            htmlFor="analysis-url"
            className="form-label"
          >
            URL à analyser
          </label>

          <div className="analysis-form__row">
            <Input
              id="analysis-url"
              type="url"
              placeholder="https://example.com"
              value={url}
              disabled={isLoading}
              autoComplete="off"
              onChange={(event) => {
                setUrl(
                  event.target.value,
                );
              }}
            />

            <Button
              type="submit"
              disabled={isLoading}
            >
              {isLoading
                ? "Analyse..."
                : "Analyser"}
            </Button>
          </div>
        </form>
      </Card>

      {isLoading && (
        <Card>
          <div className="loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Analyse en cours...
            </span>
          </div>
        </Card>
      )}

      {error && (
        <Card>
          <div className="error-state">
            <strong>
              Analyse impossible
            </strong>

            <span>
              {error}
            </span>
          </div>
        </Card>
      )}

      {result && (
        <Card>
          <div className="result-header">
            <div>
              <span className="result-label">
                Verdict
              </span>

              <h2>
                {result.verdict ===
                "benign"
                  ? "URL bénigne"
                  : "URL malveillante"}
              </h2>
            </div>

            <Badge
              tone={
                result.verdict ===
                "benign"
                  ? "success"
                  : "danger"
              }
            >
              {result.verdict}
            </Badge>
          </div>

          <div className="result-grid">
            <div>
              <span>
                Classification
              </span>

              <strong>
                {result.threat_class}
              </strong>
            </div>

            <div>
              <span>
                Confiance
              </span>

              <strong>
                {(
                  result.confidence *
                  100
                ).toFixed(1)}
                %
              </strong>
            </div>

            <div>
              <span>
                Modèle
              </span>

              <strong>
                {result.model_version}
              </strong>
            </div>
          </div>
        </Card>
      )}
    </main>
  );
}