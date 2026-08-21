import {
  Card,
} from "../components/ui/Card";


type SecurityPlaceholderPageProps = {
  title: string;
  description: string;
};


export function SecurityPlaceholderPage({
  title,
  description,
}: SecurityPlaceholderPageProps) {
  return (
    <main className="security-page">
      <header className="security-page-header">
        <h1>
          {title}
        </h1>

        <p>
          {description}
        </p>
      </header>

      <Card>
        <div className="placeholder-state">
          <span className="placeholder-state__label">
            Prochaine étape
          </span>

          <strong>
            Connexion aux données FastAPI
          </strong>

          <p>
            Aucun contenu métier simulé
            n'est affiché sur cet écran.
          </p>
        </div>
      </Card>
    </main>
  );
}