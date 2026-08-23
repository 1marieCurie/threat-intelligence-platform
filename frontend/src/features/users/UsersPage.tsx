import {
  useState,
} from "react";

import type {
  FormEvent,
} from "react";

import {
  UserPlus,
  Users,
} from "lucide-react";

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
  createStaffAccount,
} from "../../lib/api";

import type {
  AuthUser,
} from "../../types/auth";

import "./UsersPage.css";


export function UsersPage() {
  const [
    displayName,
    setDisplayName,
  ] = useState("");

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
  >(null);

  const [
    createdUser,
    setCreatedUser,
  ] = useState<
    AuthUser | null
  >(null);


  async function handleSubmit(
    event: FormEvent,
  ) {
    event.preventDefault();

    setError(
      null,
    );

    setCreatedUser(
      null,
    );

    setIsSubmitting(
      true,
    );

    try {
      const user =
        await createStaffAccount({
          display_name:
            displayName,

          email,
          password,
        });

      setCreatedUser(
        user,
      );

      setDisplayName(
        "",
      );

      setEmail(
        "",
      );

      setPassword(
        "",
      );

    } catch (
      caughtError
    ) {
      setError(
        caughtError
          instanceof Error
          ? caughtError.message
          : (
            "Impossible de créer "
            + "ce compte."
          ),
      );

    } finally {
      setIsSubmitting(
        false,
      );
    }
  }


  return (
    <div className="users-page">
      <header className="users-header">
        <div>
          <span className="users-eyebrow">
            Organisation
          </span>

          <h1>
            Utilisateurs
          </h1>

          <p>
            Créez les comptes staff
            autorisés à utiliser
            l’analyse URL.
          </p>
        </div>

        <div className="users-header-icon">
          <Users
            size={22}
            strokeWidth={1.8}
          />
        </div>
      </header>

      <Card className="users-create-card">
        <div className="users-card-heading">
          <div className="users-card-icon">
            <UserPlus
              size={18}
              strokeWidth={1.8}
            />
          </div>

          <div>
            <h2>
              Nouveau compte staff
            </h2>

            <p>
              Le rôle et l’organisation
              sont définis automatiquement.
            </p>
          </div>
        </div>

        <form
          className="users-form"
          onSubmit={
            handleSubmit
          }
        >
          <label className="users-field">
            <span>
              Nom
            </span>

            <Input
              type="text"
              value={
                displayName
              }
              autoComplete="name"
              placeholder="Nom du collaborateur"
              required
              maxLength={255}
              disabled={
                isSubmitting
              }
              onChange={(
                event,
              ) => {
                setDisplayName(
                  event.target.value,
                );
              }}
            />
          </label>

          <label className="users-field">
            <span>
              Adresse e-mail
            </span>

            <Input
              type="email"
              value={email}
              autoComplete="email"
              placeholder="collaborateur@entreprise.ma"
              required
              maxLength={320}
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

          <label className="users-field">
            <span>
              Mot de passe initial
            </span>

            <Input
              type="password"
              value={password}
              autoComplete="new-password"
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
              className="users-error"
              role="alert"
            >
              {error}
            </div>
          )}

          {createdUser && (
            <div
              className="users-success"
              role="status"
            >
              <strong>
                Compte créé.
              </strong>

              <span>
                {createdUser.display_name}
                {" — "}
                {createdUser.email}
              </span>

              <span>
                Rôle : staff
              </span>
            </div>
          )}

          <div className="users-actions">
            <Button
              type="submit"
              disabled={
                isSubmitting
              }
            >
              {isSubmitting
                ? "Création..."
                : "Créer le compte"}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}