import {
  useState,
} from "react";

import type {
  FormEvent,
} from "react";

import {
  ArrowLeft,
  ShieldCheck,
} from "lucide-react";

import {
  Link,
  useNavigate,
} from "react-router";

import {
  Button,
} from "../../components/ui/Button";
import {
  Input,
} from "../../components/ui/Input";
import {
  registerOrganization,
} from "../../lib/api";


export function RegisterPage() {
  const navigate = useNavigate();

  const [organizationName, setOrganizationName] = useState("");
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const result = await registerOrganization({
        organization_name: organizationName,
        organization_slug: organizationSlug,
        display_name: displayName,
        email,
        password,
      });

      const params = new URLSearchParams({
        organization_slug: result.organization_slug,
        registered: "1",
      });

      navigate(
        `/connexion?${params.toString()}`,
        { replace: true },
      );
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Inscription impossible.",
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-panel auth-panel--register">
        <Link to="/" className="auth-back-link">
          <ArrowLeft size={14} />
          Retour à l'accueil
        </Link>

        <div className="auth-brand">
          <div className="brand-mark platform-brand-mark" aria-hidden="true">
            <ShieldCheck size={18} strokeWidth={1.8} />
          </div>
          <div>
            <strong>Threat Intelligence</strong>
            <span>Platform</span>
          </div>
        </div>

        <div className="auth-heading">
          <span className="auth-eyebrow">Nouvelle organisation</span>
          <h1>Inscription</h1>
          <p>
            Créez votre organisation et son premier compte responsable sécurité.
          </p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          <label className="auth-field">
            <span>Nom de l’organisation</span>
            <Input
              type="text"
              value={organizationName}
              autoComplete="organization"
              placeholder="Mon Entreprise"
              required
              maxLength={255}
              disabled={isSubmitting}
              onChange={(event) => setOrganizationName(event.target.value)}
            />
          </label>

          <label className="auth-field">
            <span>Slug de l’organisation</span>
            <Input
              type="text"
              value={organizationSlug}
              placeholder="mon-entreprise"
              required
              maxLength={63}
              pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
              title="Lettres minuscules, chiffres et tirets uniquement."
              disabled={isSubmitting}
              onChange={(event) => setOrganizationSlug(event.target.value)}
            />
            <small className="auth-help">
              Identifiant court utilisé lors de la connexion.
            </small>
          </label>

          <label className="auth-field">
            <span>Votre nom</span>
            <Input
              type="text"
              value={displayName}
              autoComplete="name"
              placeholder="Nom complet"
              required
              maxLength={255}
              disabled={isSubmitting}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </label>

          <label className="auth-field">
            <span>Adresse e-mail</span>
            <Input
              type="email"
              value={email}
              autoComplete="email"
              placeholder="security@entreprise.ma"
              required
              maxLength={320}
              disabled={isSubmitting}
              onChange={(event) => setEmail(event.target.value)}
            />
          </label>

          <label className="auth-field">
            <span>Mot de passe</span>
            <Input
              type="password"
              value={password}
              autoComplete="new-password"
              required
              disabled={isSubmitting}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>

          {error && (
            <div className="auth-error" role="alert">
              {error}
            </div>
          )}

          <Button
            type="submit"
            disabled={isSubmitting}
            className="auth-submit"
          >
            {isSubmitting ? "Création..." : "Créer l’organisation"}
          </Button>
        </form>

        <div className="auth-switch">
          <span>Vous avez déjà un compte ?</span>
          <Link to="/connexion">Se connecter</Link>
        </div>

        <Link to="/aide#demarrage" className="auth-help-center-link">
          Consulter le guide de démarrage
        </Link>
      </section>
    </main>
  );
}
