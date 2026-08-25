import {
  useState,
} from "react";

import type {
  FormEvent,
} from "react";

import {
  BookOpen,
  CircleCheck,
  CircleX,
  Cpu,
  Gauge,
  Globe2,
  Link2,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import {
  Link,
} from "react-router";

import {
  Button,
} from "../../components/ui/Button";
import {
  Card,
} from "../../components/ui/Card";
import {
  Input,
} from "../../components/ui/Input";
import {
  analyzeURL,
} from "../../lib/api";
import type {
  URLAnalysisResult,
  URLThreatClass,
} from "../../types/urlAnalysis";

import "./url-analysis.css";
import "./url-analysis-polish.css";


function displayThreatClass(
  value: URLThreatClass,
): string {
  if (value === "benign") {
    return "Bénigne";
  }

  if (value === "phishing") {
    return "Phishing";
  }

  return "Malware";
}


export function URLAnalysisPage() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<URLAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    const value = url.trim();

    if (!value) {
      setResult(null);
      setError("Veuillez saisir une URL.");
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      setResult(await analyzeURL(value));
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

  const isBenign = result?.verdict === "benign";

  return (
    <main className="url-analysis-page">
      <header className="url-analysis-header url-analysis-header--with-help">
        <div>
          <span className="url-analysis-eyebrow">Analyse temps réel</span>
          <h1>Analyse d'URL</h1>
          <p>
            Vérifiez une adresse web avec le moteur de classification de menaces de la plateforme.
          </p>
        </div>

        <Link to="/aide#url" className="url-analysis-help-link">
          <BookOpen size={15} />
          Comment lire le résultat ?
        </Link>
      </header>

      <Card className="url-analysis-workspace">
        <div className="url-analysis-workspace__heading">
          <span className="url-analysis-workspace__icon">
            <Globe2 size={17} strokeWidth={1.7} />
          </span>
          <div>
            <strong>Vérifier une adresse</strong>
            <span>Entrez une URL complète commençant par http:// ou https://.</span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="url-analysis-form">
          <label htmlFor="analysis-url" className="form-label">
            URL à analyser
          </label>

          <div className="url-analysis-form__row">
            <div className="url-analysis-input">
              <Link2
                size={16}
                strokeWidth={1.8}
                aria-hidden="true"
              />
              <Input
                id="analysis-url"
                type="url"
                placeholder="https://example.com"
                value={url}
                disabled={isLoading}
                autoComplete="off"
                onChange={(event) => setUrl(event.target.value)}
              />
            </div>

            <Button
              type="submit"
              disabled={isLoading}
              className="url-analysis-submit"
            >
              <ScanSearch size={15} strokeWidth={1.8} />
              {isLoading ? "Analyse..." : "Analyser"}
            </Button>
          </div>
        </form>

        {isLoading && (
          <div className="url-analysis-loading" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            <div>
              <strong>Analyse en cours</strong>
              <span>Le modèle examine cette adresse web.</span>
            </div>
          </div>
        )}

        {error && (
          <div className="url-analysis-error" role="alert">
            <span className="url-analysis-error__icon">
              <CircleX size={16} strokeWidth={1.9} />
            </span>
            <div>
              <strong>Analyse impossible</strong>
              <span>{error}</span>
            </div>
          </div>
        )}
      </Card>

      {result && (
        <section
          className={
            `url-result ${isBenign
              ? "url-result--benign"
              : "url-result--malicious"}`
          }
          aria-live="polite"
        >
          <div className="url-result__main">
            <span className="url-result__icon">
              {isBenign ? (
                <ShieldCheck size={23} strokeWidth={1.7} />
              ) : (
                <ShieldAlert size={23} strokeWidth={1.7} />
              )}
            </span>

            <div className="url-result__verdict">
              <span>Verdict</span>
              <h2>{isBenign ? "URL bénigne" : "URL malveillante"}</h2>
              <p>
                {isBenign
                  ? "Le modèle n'a pas identifié de caractéristiques malveillantes dans cette analyse."
                  : "Cette adresse présente des caractéristiques associées à une menace selon le modèle."}
              </p>
            </div>

            <span className="url-result__status">
              {isBenign ? (
                <CircleCheck size={13} strokeWidth={2} />
              ) : (
                <ShieldAlert size={13} strokeWidth={1.9} />
              )}
              {result.verdict}
            </span>
          </div>

          <div className="url-result__details">
            <div className="url-result-fact">
              <span className="url-result-fact__icon">
                {isBenign ? (
                  <ShieldCheck size={15} strokeWidth={1.8} />
                ) : (
                  <ShieldAlert size={15} strokeWidth={1.8} />
                )}
              </span>
              <div>
                <strong>{displayThreatClass(result.threat_class)}</strong>
                <span>Classification</span>
              </div>
            </div>

            <div className="url-result-fact">
              <span className="url-result-fact__icon">
                <Gauge size={15} strokeWidth={1.8} />
              </span>
              <div>
                <strong>{(result.confidence * 100).toFixed(1)}%</strong>
                <span>Confiance du modèle</span>
              </div>
            </div>

            <div className="url-result-fact">
              <span className="url-result-fact__icon">
                <Cpu size={15} strokeWidth={1.8} />
              </span>
              <div>
                <strong>{result.model_version}</strong>
                <span>Version du modèle</span>
              </div>
            </div>
          </div>

          <p className="url-result-disclaimer">
            Ce verdict est une aide à la décision produite par un modèle de classification ; il ne constitue pas une garantie absolue qu'une URL est sûre ou compromise.
          </p>
        </section>
      )}
    </main>
  );
}
