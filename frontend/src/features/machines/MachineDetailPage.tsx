import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  ArrowLeft,
  Boxes,
  Clock3,
  Cpu,
  Fingerprint,
  Monitor,
  Package,
  Search,
  ShieldAlert,
  Zap,
} from "lucide-react";

import type {
  LucideIcon,
} from "lucide-react";

import {
  Link,
  useParams,
} from "react-router";

import {
  Card,
} from "../../components/ui/Card";

import {
  Input,
} from "../../components/ui/Input";

import {
  Table,
} from "../../components/ui/Table";

import {
  getMachineDetail,
} from "../../lib/api";

import type {
  MachineDetail,
} from "../../types/machine";

import "./machines.css";


function formatInventoryDate(
  value: string | null,
): string {
  if (!value) {
    return "Jamais";
  }

  const date = new Date(
    value,
  );

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return value;
  }

  return new Intl.DateTimeFormat(
    "fr-FR",
    {
      dateStyle: "medium",
      timeStyle: "short",
    },
  ).format(
    date,
  );
}


function displayValue(
  value:
    | string
    | null,
): string {
  return value?.trim()
    || "Non renseigné";
}


type MachineFactProps = {
  icon: LucideIcon;
  label: string;
  value: string | number;
  compact?: boolean;
};


function MachineFact({
  icon: Icon,
  label,
  value,
  compact = false,
}: MachineFactProps) {
  return (
    <div className="machine-fact">
      <span className="machine-fact__icon">
        <Icon
          size={17}
          strokeWidth={1.8}
        />
      </span>

      <div className="machine-fact__content">
        <strong
          className={
            compact
              ? (
                "machine-fact__value "
                + "machine-fact__value--compact"
              )
              : "machine-fact__value"
          }
        >
          {value}
        </strong>

        <span className="machine-fact__label">
          {label}
        </span>
      </div>
    </div>
  );
}


function priorityClass(
  priority: string | null,
): string {
  if (!priority) {
    return "priority-tag";
  }

  return (
    "priority-tag "
    + `priority-tag--${priority.toLowerCase()}`
  );
}


export function MachineDetailPage() {
  const {
    machineId,
  } = useParams();

  const [
    machine,
    setMachine,
  ] = useState<
    MachineDetail | null
  >(null);

  const [
    componentSearch,
    setComponentSearch,
  ] = useState("");

  const [
    isLoading,
    setIsLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState<
    string | null
  >(null);


  useEffect(() => {
    let cancelled = false;

    async function loadMachine() {
      if (!machineId) {
        setError(
          "Identifiant machine invalide.",
        );

        setIsLoading(false);

        return;
      }

      setIsLoading(true);
      setError(null);

      try {
        const result =
          await getMachineDetail(
            machineId,
          );

        if (!cancelled) {
          setMachine(
            result,
          );
        }
      } catch (caughtError) {
        if (!cancelled) {
          setError(
            caughtError
              instanceof Error
              ? caughtError.message
              : (
                "Une erreur inattendue "
                + "est survenue."
              ),
          );
        }
      } finally {
        if (!cancelled) {
          setIsLoading(
            false,
          );
        }
      }
    }

    void loadMachine();

    return () => {
      cancelled = true;
    };
  }, [
    machineId,
  ]);


  const filteredComponents =
    useMemo(() => {
      if (!machine) {
        return [];
      }

      const value =
        componentSearch
          .trim()
          .toLowerCase();

      if (!value) {
        return machine.components;
      }

      return machine.components.filter(
        (component) => {
          const searchable = [
            component.name,
            component.version,
            component.vendor,
            component.component_type,
            component.ecosystem,
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();

          return searchable.includes(
            value,
          );
        },
      );
    }, [
      machine,
      componentSearch,
    ]);


  if (isLoading) {
    return (
      <main className="security-page">
        <Card>
          <div className="loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Chargement de la machine...
            </span>
          </div>
        </Card>
      </main>
    );
  }


  if (
    error
    || !machine
  ) {
    return (
      <main className="security-page">
        <Link
          to="/machines"
          className="machine-back-link"
        >
          <ArrowLeft
            size={15}
            strokeWidth={1.8}
          />

          Retour aux machines
        </Link>

        <Card>
          <div className="error-state">
            <strong>
              Machine indisponible
            </strong>

            <span>
              {
                error
                ?? "Machine introuvable."
              }
            </span>
          </div>
        </Card>
      </main>
    );
  }


  return (
    <main className="security-page">
      <Link
        to="/machines"
        className="machine-back-link"
      >
        <ArrowLeft
          size={15}
          strokeWidth={1.8}
        />

        Retour aux machines
      </Link>

      <header className="security-page-header machine-detail-page-header">
        <div>
          <span className="machine-detail-eyebrow">
            Fiche machine
          </span>

          <h1>
            {machine.hostname}
          </h1>

          <p>
            Inventaire logiciel et
            expositions associées à cette
            machine.
          </p>
        </div>

        <span className="machine-header-id">
          <Fingerprint
            size={14}
            strokeWidth={1.8}
          />

          {
            machine.machine_id.slice(
              0,
              8,
            )
          }
        </span>
      </header>

      <section
        className="machine-facts"
        aria-label="Informations de la machine"
      >
        <MachineFact
          icon={Monitor}
          label="Système"
          value={
            `${machine.os_name} ${machine.os_version}`
          }
          compact
        />

        <MachineFact
          icon={Cpu}
          label="Architecture"
          value={
            machine.architecture
          }
        />

        <MachineFact
          icon={Clock3}
          label="Dernier inventaire"
          value={
            formatInventoryDate(
              machine.last_inventory_at,
            )
          }
          compact
        />

        <MachineFact
          icon={Boxes}
          label="Composants"
          value={
            machine.components.length
          }
        />

        <MachineFact
          icon={ShieldAlert}
          label="Expositions"
          value={
            machine.exposures.length
          }
        />

        <MachineFact
          icon={Fingerprint}
          label="Machine UID"
          value={
            machine.machine_uid
          }
          compact
        />
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div className="machine-section-title">
            <span className="machine-section-icon">
              <Package
                size={16}
                strokeWidth={1.8}
              />
            </span>

            <div>
              <h2>
                Inventaire logiciel
              </h2>

              <p>
                Composants détectés lors du
                dernier inventaire.
              </p>
            </div>
          </div>

          <div className="machine-component-search">
            <Search
              size={15}
              strokeWidth={1.8}
              aria-hidden="true"
            />

            <Input
              type="search"
              placeholder="Rechercher un logiciel..."
              aria-label="Rechercher un logiciel"
              value={componentSearch}
              onChange={(event) => {
                setComponentSearch(
                  event.target.value,
                );
              }}
            />
          </div>
        </div>

        {filteredComponents.length === 0 ? (
          <Card className="machine-empty-panel">
            <Package
              size={22}
              strokeWidth={1.6}
            />

            <strong>
              Aucun composant
            </strong>

            <span>
              Aucun logiciel ne correspond
              à cette recherche.
            </span>
          </Card>
        ) : (
          <Table className="machine-components-table">
            <thead>
              <tr>
                <th>
                  Type
                </th>

                <th>
                  Logiciel
                </th>

                <th>
                  Version
                </th>

                <th>
                  Vendor / Écosystème
                </th>

                <th>
                  Détection
                </th>
              </tr>
            </thead>

            <tbody>
              {filteredComponents.map(
                (component) => (
                  <tr
                    key={
                      component.component_id
                    }
                  >
                    <td>
                      <span
                        className={
                          (
                            "component-type "
                            + `component-type--${component.component_type}`
                          )
                        }
                      >
                        {
                          component.component_type
                        }
                      </span>
                    </td>

                    <td>
                      <strong className="component-name">
                        {component.name}
                      </strong>
                    </td>

                    <td>
                      {displayValue(
                        component.version,
                      )}
                    </td>

                    <td>
                      {displayValue(
                        component.vendor
                        ?? component.ecosystem,
                      )}
                    </td>

                    <td>
                      <span className="detector-value">
                        {
                          component.detected_by
                        }
                      </span>
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </Table>
        )}
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div className="machine-section-title">
            <span className="machine-section-icon machine-section-icon--danger">
              <ShieldAlert
                size={16}
                strokeWidth={1.8}
              />
            </span>

            <div>
              <h2>
                Expositions associées
              </h2>

              <p>
                Vulnérabilités corrélées aux
                composants de cette machine.
              </p>
            </div>
          </div>
        </div>

        {machine.exposures.length === 0 ? (
          <Card className="machine-empty-panel">
            <ShieldAlert
              size={22}
              strokeWidth={1.6}
            />

            <strong>
              Aucune exposition détectée
            </strong>

            <span>
              Aucune vulnérabilité n'est
              actuellement associée aux
              composants de cette machine.
            </span>
          </Card>
        ) : (
          <Table className="machine-exposures-table">
            <thead>
              <tr>
                <th>
                  Vulnérabilité
                </th>

                <th>
                  Composant
                </th>

                <th>
                  Applicabilité
                </th>

                <th>
                  Severity
                </th>

                <th>
                  Priority
                </th>

                <th>
                  KEV
                </th>

                <th>
                  Matching
                </th>
              </tr>
            </thead>

            <tbody>
              {machine.exposures.map(
                (exposure) => (
                  <tr
                    key={
                      exposure.exposure_id
                    }
                  >
                    <td>
                      <strong className="vulnerability-identifier">
                        {
                          exposure
                            .primary_identifier
                          ?? (
                            exposure
                              .canonical_vulnerability_id
                              .slice(
                                0,
                                8,
                              )
                          )
                        }
                      </strong>
                    </td>

                    <td>
                      <strong className="machine-exposure-component">
                        {
                          exposure
                            .component_name
                        }
                      </strong>

                      <div className="table-secondary">
                        {
                          exposure
                            .component_version
                          ?? "Version inconnue"
                        }
                      </div>
                    </td>

                    <td>
                      <span
                        className={
                          (
                            "applicability-badge "
                            + `applicability-badge--${exposure.applicability_status}`
                          )
                        }
                      >
                        {
                          exposure
                            .applicability_status
                        }
                      </span>
                    </td>

                    <td>
                      {
                        exposure.severity
                        ?? "—"
                      }
                    </td>

                    <td>
                      <span
                        className={
                          priorityClass(
                            exposure.priority,
                          )
                        }
                      >
                        {
                          exposure.priority
                          ?? "—"
                        }
                      </span>
                    </td>

                    <td>
                      {exposure.is_kev ? (
                        <span className="kev-indicator">
                          <Zap
                            size={12}
                            strokeWidth={1.9}
                          />

                          KEV
                        </span>
                      ) : (
                        <span className="machine-muted-value">
                          —
                        </span>
                      )}
                    </td>

                    <td>
                      <span className="detector-value">
                        {
                          exposure.match_rule
                        }
                      </span>

                      {exposure.match_version && (
                        <div className="table-secondary">
                          {
                            exposure
                              .match_version
                          }
                        </div>
                      )}
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </Table>
        )}
      </section>
    </main>
  );
}