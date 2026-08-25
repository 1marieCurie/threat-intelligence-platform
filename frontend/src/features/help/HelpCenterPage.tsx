import {
  BellRing,
  BookOpen,
  CircleHelp,
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
  Card,
} from "../../components/ui/Card";
import {
  useAuth,
} from "../../context/AuthContext";

import "./help-center.css";


const publicTopics = [
  ["presentation", "Présentation"],
  ["demarrage", "Démarrage"],
  ["url", "Analyse URL"],
  ["inventaire", "Machines et logiciels"],
  ["vulnerabilites", "Vulnérabilités"],
  ["alertes", "Alertes"],
  ["faq", "FAQ"],
  ["glossaire", "Glossaire"],
] as const;

const securityTopics = [
  ["presentation", "Présentation"],
  ["demarrage", "Routine de démarrage"],
  ["url", "Analyse URL"],
  ["inventaire", "Machines et logiciels"],
  ["vulnerabilites", "Vulnérabilités"],
  ["triage", "Triage et décision"],
  ["alertes", "Alertes"],
  ["faq", "FAQ opérationnelle"],
  ["glossaire", "Glossaire"],
] as const;


export function HelpCenterPage() {
  const { user } = useAuth();
  const isSecurityResponsible = user?.role === "security_responsible";
  const topics = isSecurityResponsible ? securityTopics : publicTopics;

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
        <span className="help-eyebrow">
          {isSecurityResponsible ? "Guide responsable sécurité" : "Centre d'aide"}
        </span>
        <h1>
          {isSecurityResponsible
            ? "Interpréter les signaux et décider quoi traiter en premier"
            : "Comprendre la plateforme sans jargon inutile"}
        </h1>
        <p>
          {isSecurityResponsible
            ? "Ce guide opérationnel explique comment lire l'inventaire, qualifier les expositions, interpréter CVSS, EPSS et CISA KEV, comprendre les priorités et décider des actions de remédiation."
            : "Ce guide est destiné en priorité au responsable d'une PME. Il explique comment utiliser la plateforme au quotidien et comment interpréter les informations de cybersécurité affichées."}
        </p>

        {isSecurityResponsible && (
          <div className="help-security-banner">
            <ShieldQuestion size={20} aria-hidden="true" />
            <div>
              <strong>Lecture opérationnelle</strong>
              <span>
                La plateforme aide à prioriser. Elle ne remplace pas la validation technique,
                la politique de patch management ni l'analyse de l'impact métier.
              </span>
            </div>
          </div>
        )}
      </section>

      <div className="help-layout">
        <aside className="help-toc" aria-label="Sujets du centre d'aide">
          <strong>{isSecurityResponsible ? "Guide opérationnel" : "Dans ce guide"}</strong>
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

            {isSecurityResponsible && (
              <div className="help-operator-grid">
                <Card>
                  <strong>Inventaire</strong>
                  <p>Détermine ce qui est réellement installé et fournit le contexte nécessaire au matching.</p>
                </Card>
                <Card>
                  <strong>Threat intelligence</strong>
                  <p>Apporte CVE, CVSS, EPSS, CWE, KEV et autres signaux utiles à l'évaluation du risque.</p>
                </Card>
                <Card>
                  <strong>Corrélation</strong>
                  <p>Relie une vulnérabilité aux logiciels et machines de l'organisation avec un niveau de confiance.</p>
                </Card>
                <Card>
                  <strong>Priorisation</strong>
                  <p>Transforme plusieurs signaux en un ordre pratique de traitement pour le responsable sécurité.</p>
                </Card>
              </div>
            )}
          </section>

          <section id="demarrage" className="help-section">
            <div className="help-section__title">
              <ShieldCheck size={22} />
              <div><span>2</span><h2>{isSecurityResponsible ? "Routine de démarrage" : "Guide de démarrage"}</h2></div>
            </div>
            <ol className="help-steps">
              <li><strong>Connexion :</strong> connectez-vous avec le slug de l'organisation, votre e-mail et votre mot de passe.</li>
              <li><strong>Dashboard :</strong> commencez par les indicateurs globaux, les expositions critiques et les actions prioritaires.</li>
              <li><strong>Machines :</strong> vérifiez que les postes ou serveurs attendus sont bien présents.</li>
              <li><strong>Logiciels :</strong> contrôlez les logiciels et versions remontés par l'inventaire.</li>
              <li><strong>Vulnérabilités :</strong> ouvrez d'abord les priorités HIGH et CRITICAL, en particulier si KEV est présent.</li>
              <li><strong>Alertes :</strong> consultez ce qui a changé et pourquoi la plateforme a déclenché une alerte.</li>
            </ol>

            {isSecurityResponsible && (
              <Card className="help-callout help-callout--security">
                <strong>Routine recommandée</strong>
                <p>
                  Vérifiez d'abord les alertes nouvelles, puis les vulnérabilités CRITICAL confirmed,
                  les entrées KEV et enfin les expositions HIGH. Contrôlez ensuite la qualité de l'inventaire
                  afin de ne pas prendre une décision sur une version absente ou obsolète.
                </p>
              </Card>
            )}
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

            {isSecurityResponsible && (
              <div className="help-technical-note">
                <strong>Interprétation responsable</strong>
                <p>
                  Un verdict benign ne doit pas être assimilé à une autorisation définitive. Pour une URL
                  sensible, récemment créée, raccourcie ou reçue dans un contexte de phishing, conservez une
                  validation humaine et les contrôles de sécurité habituels de l'entreprise.
                </p>
              </div>
            )}
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

            {isSecurityResponsible && (
              <>
                <h3>Pourquoi la qualité de version est importante</h3>
                <p>
                  Les vulnérabilités sont souvent liées à des plages de versions. Une version exacte permet
                  un rapprochement plus fort. Une version absente, ambiguë ou non normalisée peut conduire à
                  une exposition <strong>potential</strong> plutôt qu'à une exposition <strong>confirmed</strong>.
                </p>
                <div className="help-checklist">
                  <strong>À contrôler après chaque import</strong>
                  <ul>
                    <li>la machine attendue est présente et son dernier inventaire est récent ;</li>
                    <li>le logiciel critique apparaît avec une version exploitable ;</li>
                    <li>les doublons ou noms inhabituels ne masquent pas un composant important ;</li>
                    <li>une baisse soudaine du nombre de composants n'est pas due à un inventaire incomplet.</li>
                  </ul>
                </div>
              </>
            )}
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

            {isSecurityResponsible && (
              <>
                <h3>Confirmed : ce que cela signifie réellement</h3>
                <p>
                  <strong>Confirmed</strong> indique que les données disponibles permettent une correspondance
                  forte entre un composant inventorié et les conditions connues de la vulnérabilité. Ce statut
                  augmente fortement la confiance opérationnelle, mais il ne prouve pas qu'une attaque a eu lieu.
                  Il signifie : « cette machine possède très probablement un composant concerné ».
                </p>

                <h3>Potential : pourquoi il ne faut pas l'ignorer</h3>
                <p>
                  <strong>Potential</strong> signifie que le logiciel semble correspondre, mais qu'une information
                  nécessaire à une confirmation stricte manque ou reste ambiguë, souvent la version exacte ou une
                  condition de matching. Ce n'est pas un faux positif par définition. Vérifiez la version installée,
                  l'éditeur, le package et les informations de la fiche avant de fermer le sujet.
                </p>

                <div className="help-signal-table" role="table" aria-label="Lecture des principaux signaux">
                  <div className="help-signal-table__row help-signal-table__row--header" role="row">
                    <span>Signal</span><span>Ce qu'il mesure</span><span>Ce qu'il ne prouve pas</span>
                  </div>
                  <div className="help-signal-table__row" role="row">
                    <strong>CVSS</strong><span>Impact et difficulté technique de l'exploitation.</span><span>Que l'exploitation est probable chez vous.</span>
                  </div>
                  <div className="help-signal-table__row" role="row">
                    <strong>EPSS</strong><span>Probabilité statistique d'exploitation observée/prévue.</span><span>L'impact métier de la faille.</span>
                  </div>
                  <div className="help-signal-table__row" role="row">
                    <strong>KEV</strong><span>Exploitation réelle connue et cataloguée par la CISA.</span><span>Que votre machine est déjà compromise.</span>
                  </div>
                  <div className="help-signal-table__row" role="row">
                    <strong>Priority</strong><span>Ordre pratique de traitement selon plusieurs signaux.</span><span>Un score universel applicable à toutes les entreprises.</span>
                  </div>
                </div>
              </>
            )}
          </section>

          {isSecurityResponsible && (
            <section id="triage" className="help-section">
              <div className="help-section__title">
                <ShieldQuestion size={22} />
                <div><span>6</span><h2>Triage et décision de remédiation</h2></div>
              </div>
              <p>
                Le triage consiste à décider dans quel ordre vérifier et corriger les expositions. Ne vous
                limitez pas au score le plus élevé : combinez applicabilité, exploitation connue, priorité,
                criticité de la machine et facilité de remédiation.
              </p>

              <div className="help-triage-flow">
                <article><span>1</span><div><strong>Confirmer l'exposition</strong><p>Commencez par confirmed. Pour potential, vérifiez la version et le contexte.</p></div></article>
                <article><span>2</span><div><strong>Chercher les signaux forts</strong><p>KEV, priorité CRITICAL, score CVSS élevé et EPSS significatif augmentent l'urgence.</p></div></article>
                <article><span>3</span><div><strong>Évaluer l'actif</strong><p>Un serveur métier ou une machine exposée peut justifier une action plus rapide.</p></div></article>
                <article><span>4</span><div><strong>Choisir l'action</strong><p>Patch, mise à niveau, désinstallation, mitigation temporaire ou validation complémentaire.</p></div></article>
                <article><span>5</span><div><strong>Réinventorier</strong><p>Après correction, un nouvel inventaire permet de vérifier que l'exposition n'est plus détectée.</p></div></article>
              </div>

              <Card className="help-callout help-callout--security">
                <strong>Ordre de lecture recommandé</strong>
                <p>
                  CRITICAL + confirmed + KEV est le cas le plus urgent. Ensuite viennent les CRITICAL confirmed,
                  les HIGH confirmed avec signaux d'exploitation, puis les potential qui concernent des actifs
                  importants ou pour lesquels la version doit être vérifiée rapidement.
                </p>
              </Card>
            </section>
          )}

          <section id="alertes" className="help-section">
            <div className="help-section__title">
              <BellRing size={22} />
              <div><span>{isSecurityResponsible ? "7" : "6"}</span><h2>Comprendre les alertes</h2></div>
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

            {isSecurityResponsible && (
              <>
                <h3>Règles d'alerte V1</h3>
                <div className="help-alert-rules">
                  <article>
                    <TriangleAlert size={18} />
                    <div><strong>Nouvelle exposition confirmed critique</strong><p>Une exposition nouvellement confirmée arrive directement avec une priorité CRITICAL.</p></div>
                  </article>
                  <article>
                    <TriangleAlert size={18} />
                    <div><strong>Entrée dans CISA KEV</strong><p>Une exposition confirmed déjà connue devient présente dans le catalogue des vulnérabilités exploitées.</p></div>
                  </article>
                  <article>
                    <TriangleAlert size={18} />
                    <div><strong>Transition vers CRITICAL</strong><p>Une exposition confirmed passe d'une priorité LOW, MEDIUM ou HIGH vers CRITICAL.</p></div>
                  </article>
                </div>
                <p>
                  Dans la version actuelle, l'alerte conserve le contexte utile du déclenchement, mais
                  toutes les valeurs historiques intermédiaires ne sont pas nécessairement persistées.
                  Utilisez la fiche d'alerte pour comprendre le signal actuel et l'actif concerné.
                </p>
              </>
            )}
          </section>

          <section id="faq" className="help-section">
            <div className="help-section__title">
              <CircleHelp size={22} />
              <div><span>{isSecurityResponsible ? "8" : "7"}</span><h2>{isSecurityResponsible ? "FAQ opérationnelle" : "FAQ"}</h2></div>
            </div>
            <details><summary>Dois-je corriger toutes les CVE immédiatement ?</summary><p>Non. Commencez par les priorités CRITICAL et HIGH, les vulnérabilités confirmed et les éléments présents dans CISA KEV.</p></details>
            <details><summary>EPSS est absent : la CVE est-elle sans danger ?</summary><p>Non. EPSS n'est qu'un signal parmi plusieurs et n'est pas disponible pour toutes les vulnérabilités.</p></details>
            <details><summary>Potential signifie-t-il faux positif ?</summary><p>Pas nécessairement. Cela signifie que le rapprochement avec la version installée est moins certain et mérite une vérification.</p></details>
            <details><summary>Que faire après une alerte ?</summary><p>Ouvrez le détail, identifiez la machine et le logiciel concernés, vérifiez les signaux de risque puis planifiez la mise à jour, la mitigation ou la vérification adaptée.</p></details>
            {isSecurityResponsible && (
              <>
                <details><summary>CVSS 9.8 veut-il dire priorité CRITICAL ?</summary><p>Pas automatiquement. CVSS mesure la sévérité technique. La priorité tient compte du contexte, de l'applicabilité et d'autres signaux comme KEV et EPSS.</p></details>
                <details><summary>Une CVE dans KEV signifie-t-elle que nous sommes compromis ?</summary><p>Non. KEV indique une exploitation réelle connue dans l'écosystème. Il augmente fortement l'urgence de vérification et de correction, mais ne prouve pas une compromission locale.</p></details>
                <details><summary>Quand réimporter un inventaire ?</summary><p>Après une vague de mises à jour, une correction importante ou lorsqu'une machine affiche des versions incomplètes. Le nouvel inventaire permet de recalculer le contexte d'exposition.</p></details>
              </>
            )}
          </section>

          <section id="glossaire" className="help-section">
            <div className="help-section__title">
              <BookOpen size={22} />
              <div><span>{isSecurityResponsible ? "9" : "8"}</span><h2>Glossaire cybersécurité</h2></div>
            </div>
            <dl className="help-glossary">
              <div><dt>CVE</dt><dd>Identifiant standard d'une vulnérabilité publique.</dd></div>
              <div><dt>CWE</dt><dd>Famille ou type de faiblesse logicielle.</dd></div>
              <div><dt>CVSS</dt><dd>Mesure de la sévérité technique d'une vulnérabilité.</dd></div>
              <div><dt>EPSS</dt><dd>Estimation de probabilité d'exploitation réelle.</dd></div>
              <div><dt>KEV</dt><dd>Known Exploited Vulnerabilities, catalogue CISA des vulnérabilités connues comme exploitées.</dd></div>
              <div><dt>Severity</dt><dd>Gravité technique intrinsèque.</dd></div>
              <div><dt>Priority</dt><dd>Ordre de traitement recommandé dans le contexte de l'organisation.</dd></div>
              <div><dt>Confirmed</dt><dd>Correspondance forte entre logiciel/version installés et vulnérabilité. Ce statut ne signifie pas compromission.</dd></div>
              <div><dt>Potential</dt><dd>Correspondance plausible mais nécessitant davantage de validation, souvent à cause d'une information de version incomplète.</dd></div>
              {isSecurityResponsible && (
                <>
                  <div><dt>Matching</dt><dd>Processus de rapprochement entre un composant inventorié et les conditions d'applicabilité d'une vulnérabilité.</dd></div>
                  <div><dt>Remédiation</dt><dd>Action qui réduit ou supprime l'exposition : patch, mise à niveau, configuration, mitigation ou retrait du composant.</dd></div>
                  <div><dt>Triage</dt><dd>Classement opérationnel des vulnérabilités afin de décider lesquelles vérifier et corriger en premier.</dd></div>
                </>
              )}
            </dl>
          </section>
        </div>
      </div>
    </main>
  );
}
