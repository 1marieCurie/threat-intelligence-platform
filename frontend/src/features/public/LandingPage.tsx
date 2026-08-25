import {
  useState,
} from "react";

import type {
  FormEvent,
} from "react";

import {
  Activity,
  BellRing,
  CheckCircle2,
  Link2,
  MonitorCog,
  ScanSearch,
  ShieldCheck,
  ShieldQuestion,
  TriangleAlert,
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
  analyzePublicURL,
} from "../../lib/publicApi";
import type {
  URLAnalysisResult,
} from "../../types/urlAnalysis";

import "./landing.css";


export function LandingPage() {
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
      setError("Veuillez saisir une URL.");
      setResult(null);
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      setResult(
        await analyzePublicURL(value),
      );
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Impossible d'analyser cette URL.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  const benign = result?.verdict === "benign";

  return (
    <div className="landing-page">
      <header className="landing-nav">
        <Link
          to="/"
          className="landing-brand"
          aria-label="Threat Intelligence Platform"
        >
          <span className="landing-brand__mark">
            <ShieldCheck size={22} strokeWidth={1.8} />
          </span>
          <span>
            <strong>Threat Intelligence</strong>
            <small>Platform</small>
          </span>
        </Link>

        <nav className="landing-nav__links" aria-label="Navigation publique">
          <a href="#solution">Solution</a>
          <a href="#fonctionnement">Fonctionnement</a>
          <Link to="/aide">Centre d'aide</Link>
        </nav>

        <div className="landing-nav__actions">
          <Link to="/connexion" className="landing-link-button">
            Connexion
          </Link>
          <Link to="/inscription" className="landing-link-button landing-link-button--primary">
            Inscription
          </Link>
        </div>
      </header>

      <main>
        <section className="landing-hero">
          <div className="landing-hero__copy">
            <span className="landing-eyebrow">Cybersécurité claire pour les PME</span>
            <h1>Détectez les menaces. Priorisez l'essentiel.</h1>
            <p>
              Une plateforme simple pour analyser les URL et aider les responsables sécurité
              à identifier les vulnérabilités qui méritent vraiment leur attention.
            </p>
            <div className="landing-hero__points">
              <span><CheckCircle2 size={16} /> Analyse URL immédiate</span>
              <span><CheckCircle2 size={16} /> Priorisation des vulnérabilités</span>
            </div>
          </div>

          <Card className="public-analysis-card">
            <div className="public-analysis-card__heading">
              <span className="public-analysis-card__icon">
                <ScanSearch size={20} />
              </span>
              <div>
                <strong>Tester une URL</strong>
                <span>Aucun compte requis.</span>
              </div>
            </div>

            <form onSubmit={handleSubmit} className="public-analysis-form">
              <label htmlFor="public-url">Adresse à analyser</label>
              <div className="public-analysis-form__row">
                <div className="public-analysis-input">
                  <Link2 size={16} aria-hidden="true" />
                  <Input
                    id="public-url"
                    type="url"
                    placeholder="https://example.com"
                    value={url}
                    disabled={isLoading}
                    onChange={(event) => setUrl(event.target.value)}
                  />
                </div>
                <Button type="submit" disabled={isLoading}>
                  {isLoading ? "Analyse..." : "Analyser"}
                </Button>
              </div>
            </form>

            {error && (
              <div className="public-analysis-message public-analysis-message--error">
                <TriangleAlert size={17} />
                <span>{error}</span>
              </div>
            )}

            {result && (
              <div
                className={
                  "public-analysis-result "
                  + (benign
                    ? "public-analysis-result--benign"
                    : "public-analysis-result--malicious")
                }
              >
                {benign ? <ShieldCheck size={23} /> : <TriangleAlert size={23} />}
                <div>
                  <span>Résultat</span>
                  <strong>{benign ? "URL bénigne" : "URL malveillante"}</strong>
                  <small>
                    Classification : {result.threat_class} · Confiance : {(result.confidence * 100).toFixed(1)}%
                  </small>
                </div>
              </div>
            )}
          </Card>
        </section>

        <section id="solution" className="landing-section">
          <div className="landing-section__heading">
            <span className="landing-eyebrow">Deux piliers</span>
            <h2>Une vision simple de votre exposition</h2>
          </div>
          <div className="landing-grid landing-grid--two">
            <Card className="landing-feature-card">
              <ScanSearch size={22} />
              <h3>Analyse des URL</h3>
              <p>
                Vérifiez rapidement une adresse web et obtenez le verdict réellement produit
                par le modèle : bénigne ou malveillante, avec sa classe de menace et sa confiance.
              </p>
            </Card>
            <Card className="landing-feature-card">
              <Activity size={22} />
              <h3>Gestion intelligente des vulnérabilités</h3>
              <p>
                Croisez inventaire logiciel, CVE, CVSS, EPSS, CISA KEV et signaux d'exploitation
                pour concentrer les efforts sur les risques les plus importants.
              </p>
            </Card>
          </div>
        </section>

        <section id="fonctionnement" className="landing-section landing-section--muted">
          <div className="landing-section__heading">
            <span className="landing-eyebrow">Fonctionnement</span>
            <h2>De l'inventaire à l'action</h2>
          </div>
          <div className="landing-grid landing-grid--three">
            <Card className="landing-step-card">
              <MonitorCog size={21} />
              <strong>1. Inventorier</strong>
              <p>Importez les logiciels présents sur les machines Windows de l'entreprise.</p>
            </Card>
            <Card className="landing-step-card">
              <ShieldQuestion size={21} />
              <strong>2. Comprendre</strong>
              <p>La plateforme rapproche les logiciels des vulnérabilités et de leurs signaux de risque.</p>
            </Card>
            <Card className="landing-step-card">
              <BellRing size={21} />
              <strong>3. Prioriser</strong>
              <p>Le responsable sécurité consulte les priorités et les alertes qui nécessitent une action.</p>
            </Card>
          </div>
        </section>

        <section className="landing-section">
          <div className="landing-section__heading">
            <span className="landing-eyebrow">Pensée pour les PME</span>
            <h2>Moins de bruit, plus de décisions utiles</h2>
          </div>
          <div className="landing-benefits">
            <span><CheckCircle2 size={17} /> Interface lisible même sans expertise avancée</span>
            <span><CheckCircle2 size={17} /> Données sensibles accessibles uniquement après connexion</span>
            <span><CheckCircle2 size={17} /> Priorités basées sur plusieurs signaux, pas sur un seul score</span>
            <span><CheckCircle2 size={17} /> Alertes centrées sur les évolutions réellement importantes</span>
          </div>
        </section>

        <section className="landing-section landing-faq">
          <div className="landing-section__heading">
            <span className="landing-eyebrow">FAQ</span>
            <h2>Questions fréquentes</h2>
          </div>
          <details>
            <summary>L'analyse URL publique est-elle limitée ?</summary>
            <p>Non. Elle est proposée directement comme démonstration fonctionnelle de la plateforme.</p>
          </details>
          <details>
            <summary>Les machines et vulnérabilités sont-elles publiques ?</summary>
            <p>Non. Le dashboard, les machines, logiciels, vulnérabilités, alertes et utilisateurs restent protégés par authentification.</p>
          </details>
          <details>
            <summary>Comment comprendre les scores et priorités ?</summary>
            <p>Le centre d'aide explique CVSS, EPSS, CISA KEV, les statuts confirmed/potential et la différence entre severity et priority.</p>
          </details>
          <Link to="/aide" className="landing-text-link">Consulter le centre d'aide →</Link>
        </section>
      </main>

      <footer className="landing-footer">
        <span>Threat Intelligence Platform</span>
        <span>Projet PFA · Cybersécurité pour PME</span>
      </footer>
    </div>
  );
}
