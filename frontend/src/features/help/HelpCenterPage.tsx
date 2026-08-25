import {
  BellRing,
  BookOpen,
  CircleHelp,
  MonitorCog,
  ScanSearch,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

import {
  Link,
} from "react-router";

import {
  Card,
} from "../../components/ui/Card";
import {
  useAuth,
} from "../../context/AuthContext";

import "./help-center.css";


const topics = [
  ["presentation", "Présentation"],
  ["demarrage", "Démarrage"],
  ["url", "Analyse URL"],
  ["inventaire", "Machines et logiciels"],
  ["vulnerabilites", "Vulnérabilités"],
  ["alertes", "Alertes"],
  ["faq", "FAQ"],
  ["glossaire", "Glossaire"],
] as const;


export function HelpCenterPage() {
  const { user } = useAuth();

  return (
    <main className="help-page">
      {user === null && (
        <header className="help-public-nav">
          <Link to="/" className="help-brand">
            <span><ShieldCheck size={21} /></span>
            <strong>Threat Intelligence Platform</strong>
          </Link>
          <div>
            <Link to="/">Accueil</Link>
            <Link to="/connexion">Connexion</Link>
          </div>
        </header>
      )}

      <section className="help-hero">
        <span className="help-eyebrow">Centre d'aide</span>
        <h1>Comprendre la plateforme sans jargon inutile</h1>
        <p>
          Ce guide est destiné en priorité au responsable d'une PME. Il explique comment utiliser
          la plateforme au quotidien et comment interpréter les informations de cybersécurité affichées.
        </p>
      </section>

      <div className="help-layout">
        <aside className="help-toc" aria-label="Sujets du centre d'aide">
          <strong>Dans ce guide</strong>
          {topics.map(([id, label]) => (
            <a key={id} href={`#${id}`}>{label}</a>
          ))}
        </aside>

        <div className="help-content">
          <section id="presentation" className="help-section">
            <div className="help-section__title">
              <BookOpen size={22} />
              <div>
                <span>1</span>
                <h2>Présentation de la plateforme</h2>
              </div>
            </div>
            <p>
              Threat Intelligence Platform aide une PME à répondre à deux questions simples :
              « cette URL semble-t-elle dangereuse ? » et « quelles vulnérabilités de nos machines
              faut-il traiter en priorité ? ».
            </p>
            <Card className="help-callout">
              <strong>Deux espaces, deux usages</strong>
              <p>
                Un membre du staff dispose principalement de l'analyse URL. Le responsable sécurité
                dispose du cockpit complet : dashboard, machines, inventaires, logiciels,
                vulnérabilités, alertes, utilisateurs et analyse URL.
              </p>
            </Card>
          </section>

          <section id="demarrage" className="help-section">
            <div className="help-section__title">
              <ShieldCheck size={22} />
              <div><span>2</span><h2>Guide de démarrage</h2></div>
            </div>
            <ol className="help-steps">
              <li><strong>Connexion :</strong> connectez-vous avec le slug de l'organisation, votre e-mail et votre mot de passe.</li>
              <li><strong>Dashboard :</strong> commencez par les indicateurs globaux, les expositions critiques et les actions prioritaires.</li>
              <li><strong>Machines :</strong> vérifiez que les postes ou serveurs attendus sont bien présents.</li>
              <li><strong>Logiciels :</strong> contrôlez les logiciels et versions remontés par l'inventaire.</li>
              <li><strong>Vulnérabilités :</strong> ouvrez d'abord les priorités HIGH et CRITICAL, en particulier si KEV est présent.</li>
              <li><strong>Alertes :</strong> consultez ce qui a changé et pourquoi la plateforme a déclenché une alerte.</li>
            </ol>
          </section>

          <section id="url" className="help-section">
            <div className="help-section__title">
              <ScanSearch size={22} />
              <div><span>3</span><h2>Analyse URL</h2></div>
            </div>
            <p>
              Collez une adresse complète commençant par <code>http://</code> ou <code>https://</code>.
              Le modèle renvoie un verdict <strong>benign</strong> ou <strong>malicious</strong>, une classe
              de menace et un niveau de confiance. La confiance indique à quel point le modèle est sûr
              de sa classification ; elle ne garantit jamais qu'une URL est sans risque dans l'absolu.
            </p>
            <p>
              L'analyse présente sur la landing page est publique et ne conserve pas d'historique.
              Les autres données de l'organisation restent protégées par authentification.
            </p>
          </section>

          <section id="inventaire" className="help-section">
            <div className="help-section__title">
              <MonitorCog size={22} />
              <div><span>4</span><h2>Machines et inventaire logiciel</h2></div>
            </div>
            <p>
              Une machine représente un poste ou un serveur de l'organisation. Son inventaire contient
              les logiciels et versions détectés. L'objectif est de savoir précisément quels composants
              sont réellement présents avant de rechercher leurs vulnérabilités.
            </p>
            <Card className="help-callout">
              <strong>Bon réflexe</strong>
              <p>
                Après un nouvel import, vérifiez le nom de la machine, la date de remontée, le nombre de
                logiciels et les versions. Une version manquante ou imprécise peut réduire la précision
                du rapprochement avec les vulnérabilités.
              </p>
            </Card>
          </section>

          <section id="vulnerabilites" className="help-section">
            <div className="help-section__title">
              <TriangleAlert size={22} />
              <div><span>5</span><h2>Comprendre les vulnérabilités</h2></div>
            </div>

            <div className="help-definition-grid">
              <Card><strong>CVE</strong><p>Identifiant public d'une vulnérabilité connue, par exemple CVE-2026-1234.</p></Card>
              <Card><strong>CWE</strong><p>Catégorie du type de faiblesse logicielle à l'origine d'une vulnérabilité.</p></Card>
              <Card><strong>CVSS</strong><p>Score de sévérité technique, généralement de 0 à 10. Il décrit la gravité potentielle.</p></Card>
              <Card><strong>EPSS</strong><p>Probabilité estimée qu'une vulnérabilité soit exploitée dans la nature. Il peut être absent.</p></Card>
              <Card><strong>CISA KEV</strong><p>Catalogue de vulnérabilités connues comme activement exploitées. Sa présence est un signal fort.</p></Card>
              <Card><strong>Confirmed / Potential</strong><p>Confirmed signifie que la version installée correspond clairement ; Potential signifie que le rapprochement est plausible mais moins certain.</p></Card>
            </div>

            <h3>LOW, MEDIUM, HIGH et CRITICAL</h3>
            <p>
              La <strong>priority</strong> indique l'ordre pratique de traitement dans votre contexte.
              La <strong>severity</strong> décrit surtout la gravité technique de la vulnérabilité.
              Une CVE peut donc avoir une sévérité élevée mais une priorité plus basse si elle ne semble
              pas exploitable dans votre contexte, et l'inverse si plusieurs signaux augmentent le risque.
            </p>

            <h3>Pourquoi une vulnérabilité peut rester importante même si des données manquent ?</h3>
            <p>
              L'absence d'EPSS ou d'un autre signal ne signifie pas « risque nul ». La plateforme combine
              les informations disponibles : sévérité, exploitation connue, présence dans KEV, qualité du
              rapprochement avec la version installée et autres signaux disponibles. Une donnée manquante
              ne doit donc pas masquer une vulnérabilité critique.
            </p>

            <h3>Lire une fiche vulnérabilité</h3>
            <p>
              Commencez par l'identifiant CVE, le logiciel et la version concernés. Regardez ensuite la
              priorité, la sévérité/CVSS, EPSS s'il existe, le statut KEV, le statut confirmed/potential,
              puis la CWE et les sources. L'objectif est de comprendre à la fois « quelle est la faille ? »,
              « nous concerne-t-elle ? » et « à quel point faut-il agir vite ? ».
            </p>
          </section>

          <section id="alertes" className="help-section">
            <div className="help-section__title">
              <BellRing size={22} />
              <div><span>6</span><h2>Comprendre les alertes</h2></div>
            </div>
            <p>
              Une alerte signale un changement suffisamment important pour mériter l'attention du
              responsable sécurité. La fiche d'alerte indique la machine, la vulnérabilité, le contexte
              et l'état d'envoi. Pour comprendre « pourquoi maintenant ? », comparez les nouveaux signaux
              avec la situation précédente : apparition dans KEV, hausse importante de priorité ou
              changement vers un niveau critique selon les règles de la plateforme.
            </p>
            <Card className="help-callout">
              <strong>Une alerte n'est pas un verdict automatique de compromission.</strong>
              <p>Elle indique qu'un risque a évolué et qu'une vérification ou une action de remédiation est recommandée.</p>
            </Card>
          </section>

          <section id="faq" className="help-section">
            <div className="help-section__title">
              <CircleHelp size={22} />
              <div><span>7</span><h2>FAQ</h2></div>
            </div>
            <details><summary>Dois-je corriger toutes les CVE immédiatement ?</summary><p>Non. Commencez par les priorités CRITICAL et HIGH, les vulnérabilités confirmed et les éléments présents dans CISA KEV.</p></details>
            <details><summary>EPSS est absent : la CVE est-elle sans danger ?</summary><p>Non. EPSS n'est qu'un signal parmi plusieurs et n'est pas disponible pour toutes les vulnérabilités.</p></details>
            <details><summary>Potential signifie-t-il faux positif ?</summary><p>Pas nécessairement. Cela signifie que le rapprochement avec la version installée est moins certain et mérite une vérification.</p></details>
            <details><summary>Que faire après une alerte ?</summary><p>Ouvrez le détail, identifiez la machine et le logiciel concernés, vérifiez les signaux de risque puis planifiez la mise à jour, la mitigation ou la vérification adaptée.</p></details>
          </section>

          <section id="glossaire" className="help-section">
            <div className="help-section__title">
              <BookOpen size={22} />
              <div><span>8</span><h2>Glossaire cybersécurité</h2></div>
            </div>
            <dl className="help-glossary">
              <div><dt>CVE</dt><dd>Identifiant standard d'une vulnérabilité publique.</dd></div>
              <div><dt>CWE</dt><dd>Famille ou type de faiblesse logicielle.</dd></div>
              <div><dt>CVSS</dt><dd>Mesure de la sévérité technique d'une vulnérabilité.</dd></div>
              <div><dt>EPSS</dt><dd>Estimation de probabilité d'exploitation réelle.</dd></div>
              <div><dt>KEV</dt><dd>Known Exploited Vulnerabilities, catalogue CISA des vulnérabilités connues comme exploitées.</dd></div>
              <div><dt>Severity</dt><dd>Gravité technique intrinsèque.</dd></div>
              <div><dt>Priority</dt><dd>Ordre de traitement recommandé dans le contexte de l'organisation.</dd></div>
              <div><dt>Confirmed</dt><dd>Correspondance forte entre logiciel/version installés et vulnérabilité.</dd></div>
              <div><dt>Potential</dt><dd>Correspondance plausible mais nécessitant davantage de prudence.</dd></div>
            </dl>
          </section>
        </div>
      </div>
    </main>
  );
}
