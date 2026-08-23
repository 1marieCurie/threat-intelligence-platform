import {
  useState,
} from "react";

import type {
  FormEvent,
} from "react";

import {
  Link,
  useNavigate,
  useSearchParams,
} from "react-router";

import {
  Button,
} from "../../components/ui/Button";

import {
  Input,
} from "../../components/ui/Input";

import {
  useAuth,
} from "../../context/AuthContext";


export function LoginPage() {
  const {
    login,
  } = useAuth();

  const navigate =
    useNavigate();

  const [
    searchParams,
  ] = useSearchParams();

  const [
    organizationSlug,
    setOrganizationSlug,
  ] = useState(
    searchParams.get(
      "organization_slug",
    ) ?? "",
  );

  const [
    email,
    setEmail,
  ] = useState("");

  const [
    password,
    setPassword,
  ] = useState("");

  const [
    isSubmitting,
    setIsSubmitting,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState<
    string | null
  >(
    null,
  );

  const registrationSucceeded =
    searchParams.get(
      "registered",
    ) === "1";


  async function handleSubmit(
    event: FormEvent,
  ) {
    event.preventDefault();

    setError(
      null,
    );

    setIsSubmitting(
      true,
    );

    try {
      const user =
        await login(
          organizationSlug,
          email,
          password,
        );

      navigate(
        user.role
          === "security_responsible"
          ? "/dashboard"
          : "/analyse-url",
        {
          replace: true,
        },
      );
    } catch (caughtError) {
      setError(
        caughtError
          instanceof Error
          ? caughtError.message
          : "Connexion impossible.",
      );
    } finally {
      setIsSubmitting(
        false,
      );
    }
  }


  return (
    <main className="auth-page">
      <section className="auth-panel">
        <div className="auth-brand">
          <div className="brand-mark">
            TI
          </div>

          <div>
            <strong>
              Threat Intelligence
            </strong>

            <span>
              Platform
            </span>
          </div>
        </div>

        <div className="auth-heading">
          <span className="auth-eyebrow">
            Accès sécurisé
          </span>

          <h1>
            Connexion
          </h1>

          <p>
            Connectez-vous à votre
            espace Threat Intelligence.
          </p>
        </div>

        {registrationSucceeded && (
          <div
            className="auth-success"
            role="status"
          >
            Votre organisation a été créée.
            Vous pouvez maintenant vous connecter.
          </div>
        )}

        <form
          className="auth-form"
          onSubmit={
            handleSubmit
          }
        >
          <label
            className="auth-field"
          >
            <span>
              Slug de l’organisation
            </span>

            <Input
              type="text"
              value={
                organizationSlug
              }
              autoComplete="organization"
              placeholder="mon-entreprise"
              required
              maxLength={63}
              disabled={
                isSubmitting
              }
              onChange={(
                event,
              ) => {
                setOrganizationSlug(
                  event.target.value,
                );
              }}
            />
          </label>

          <label
            className="auth-field"
          >
            <span>
              Adresse e-mail
            </span>

            <Input
              type="email"
              value={email}
              autoComplete="email"
              placeholder="nom@entreprise.ma"
              required
              disabled={
                isSubmitting
              }
              onChange={(
                event,
              ) => {
                setEmail(
                  event.target.value,
                );
              }}
            />
          </label>

          <label
            className="auth-field"
          >
            <span>
              Mot de passe
            </span>

            <Input
              type="password"
              value={password}
              autoComplete="current-password"
              required
              disabled={
                isSubmitting
              }
              onChange={(
                event,
              ) => {
                setPassword(
                  event.target.value,
                );
              }}
            />
          </label>

          {error && (
            <div
              className="auth-error"
              role="alert"
            >
              {error}
            </div>
          )}

          <Button
            type="submit"
            disabled={
              isSubmitting
            }
            className="auth-submit"
          >
            {isSubmitting
              ? "Connexion..."
              : "Se connecter"}
          </Button>
        </form>

        <div className="auth-switch">
          <span>
            Nouvelle organisation ?
          </span>

          <Link
            to="/inscription"
          >
            Créer un compte
          </Link>
        </div>
      </section>
    </main>
  );
}