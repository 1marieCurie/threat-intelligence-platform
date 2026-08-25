import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  BookOpen,
  ChevronRight,
  Monitor,
  MonitorOff,
  RefreshCw,
  Search,
  Upload,
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
  Table,
} from "../../components/ui/Table";
import {
  getMachines,
} from "../../lib/api";
import type {
  MachineSummary,
} from "../../types/machine";

import "./machines.css";
import "./machines-polish.css";


function formatInventoryDate(
  value: string | null,
): string {
  if (!value) {
    return "Jamais";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(
    "fr-FR",
    {
      dateStyle: "medium",
      timeStyle: "short",
    },
  ).format(date);
}


export function MachinesPage() {
  const [machines, setMachines] = useState<MachineSummary[]>([]);
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadMachines = useCallback(
    async () => {
      setIsLoading(true);
      setError(null);

      try {
        const response = await getMachines();
        setMachines(response.items);
      } catch (caughtError) {
        setMachines([]);
        setError(
          caughtError instanceof Error
            ? caughtError.message
            : "Une erreur inattendue est survenue.",
        );
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void loadMachines();
  }, [loadMachines]);

  const filteredMachines = useMemo(() => {
    const value = search.trim().toLowerCase();

    if (!value) {
      return machines;
    }

    return machines.filter((machine) => {
      const searchable = [
        machine.hostname,
        machine.os_name,
        machine.os_version,
        machine.architecture,
      ]
        .join(" ")
        .toLowerCase();

      return searchable.includes(value);
    });
  }, [machines, search]);

  return (
    <main className="security-page">
      <header className="security-page-header machines-page-header">
        <div className="machines-page-header__row">
          <div>
            <h1>Machines</h1>
            <p>
              Inventaire des machines de l'organisation et synthèse de leur exposition aux vulnérabilités.
            </p>
          </div>

          <div className="machines-page-header__actions">
            <Link
              to="/aide#inventaire"
              className="machines-header-link"
            >
              <BookOpen size={15} />
              En savoir plus
            </Link>

            <Link
              to="/inventaires"
              className="machines-header-link machines-header-link--primary"
            >
              <Upload size={15} />
              Importer un inventaire
            </Link>
          </div>
        </div>
      </header>

      {isLoading && (
        <Card>
          <div className="loading-state machines-loading-state" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            <div>
              <strong>Chargement des machines</strong>
              <span>Récupération de l'inventaire et des indicateurs d'exposition...</span>
            </div>
          </div>
        </Card>
      )}

      {error && (
        <Card>
          <div className="machines-error-state" role="alert">
            <div>
              <strong>Machines indisponibles</strong>
              <span>{error}</span>
            </div>
            <Button
              type="button"
              onClick={() => {
                void loadMachines();
              }}
            >
              <RefreshCw size={14} />
              Réessayer
            </Button>
          </div>
        </Card>
      )}

      {!isLoading && !error && machines.length === 0 && (
        <Card className="machines-empty-panel">
          <MonitorOff
            size={25}
            strokeWidth={1.6}
            className="machines-empty-icon"
          />
          <strong>Aucune machine inventoriée</strong>
          <p>
            Aucun inventaire machine n'a encore été importé. Importez le premier fichier pour alimenter les vues Machines, Logiciels et Vulnérabilités.
          </p>
          <Link
            to="/inventaires"
            className="machines-empty-action"
          >
            Importer un inventaire
          </Link>
        </Card>
      )}

      {!isLoading && !error && machines.length > 0 && (
        <>
          <section className="machines-controls">
            <div className="machines-count">
              <span className="machines-count__icon">
                <Monitor size={17} strokeWidth={1.8} />
              </span>
              <div>
                <strong>{machines.length}</strong>
                <span>
                  machine{machines.length !== 1 ? "s" : ""} inventoriée{machines.length !== 1 ? "s" : ""}
                </span>
              </div>
            </div>

            <div className="machines-search">
              <Search
                size={15}
                strokeWidth={1.8}
                aria-hidden="true"
              />
              <Input
                type="search"
                placeholder="Rechercher une machine..."
                aria-label="Rechercher une machine"
                value={search}
                onChange={(event) => {
                  setSearch(event.target.value);
                }}
              />
            </div>
          </section>

          {filteredMachines.length === 0 ? (
            <Card className="machines-empty-panel">
              <Search
                size={23}
                strokeWidth={1.6}
                className="machines-empty-icon"
              />
              <strong>Aucun résultat</strong>
              <p>Aucune machine ne correspond à « {search.trim()} ».</p>
              <button
                type="button"
                className="machines-reset-search"
                onClick={() => setSearch("")}
              >
                Effacer la recherche
              </button>
            </Card>
          ) : (
            <Table className="machines-table">
              <thead>
                <tr>
                  <th>Machine</th>
                  <th>Système</th>
                  <th>Architecture</th>
                  <th>Dernier inventaire</th>
                  <th className="table-number">Composants</th>
                  <th className="table-number">Expositions</th>
                  <th className="table-number">Critiques</th>
                  <th className="table-number">KEV</th>
                  <th
                    className="machines-table__action-heading"
                    aria-label="Actions"
                  />
                </tr>
              </thead>

              <tbody>
                {filteredMachines.map((machine) => (
                  <tr key={machine.machine_id}>
                    <td>
                      <div className="machine-primary-cell">
                        <span className="machine-row-icon">
                          <Monitor size={15} strokeWidth={1.8} />
                        </span>
                        <div className="machine-name-cell">
                          <Link
                            to={`/machines/${machine.machine_id}`}
                            className="machine-name-link"
                          >
                            {machine.hostname}
                          </Link>
                          <span>{machine.machine_id.slice(0, 8)}</span>
                        </div>
                      </div>
                    </td>

                    <td>
                      <div className="machine-os-cell">
                        <strong>{machine.os_name}</strong>
                        <span>{machine.os_version}</span>
                      </div>
                    </td>

                    <td>{machine.architecture}</td>
                    <td>{formatInventoryDate(machine.last_inventory_at)}</td>
                    <td className="table-number">{machine.component_count}</td>
                    <td className="table-number">{machine.exposure_count}</td>
                    <td className="table-number">
                      <span
                        className={
                          machine.critical_exposure_count > 0
                            ? "machine-table-value machine-table-value--critical"
                            : "machine-table-value"
                        }
                      >
                        {machine.critical_exposure_count}
                      </span>
                    </td>
                    <td className="table-number">
                      <span
                        className={
                          machine.kev_exposure_count > 0
                            ? "machine-table-value machine-table-value--critical"
                            : "machine-table-value"
                        }
                      >
                        {machine.kev_exposure_count}
                      </span>
                    </td>
                    <td className="machines-table__action">
                      <Link
                        to={`/machines/${machine.machine_id}`}
                        className="machine-open-link"
                        aria-label={`Ouvrir ${machine.hostname}`}
                      >
                        <ChevronRight size={17} strokeWidth={1.8} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </>
      )}
    </main>
  );
}
