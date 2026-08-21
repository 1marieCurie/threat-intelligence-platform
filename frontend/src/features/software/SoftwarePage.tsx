import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  AppWindow,
  Boxes,
  Package,
  PackageOpen,
  Search,
  ShieldAlert,
} from "lucide-react";

import type {
  LucideIcon,
} from "lucide-react";

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
  getSoftware,
} from "../../lib/api";

import type {
  SoftwareSummary,
} from "../../types/software";

import "./software.css";


type SoftwareTypeFilter =
  | "all"
  | "application"
  | "package";


type SoftwareSort =
  | "name"
  | "machines"
  | "exposures";


function isSoftwareTypeFilter(
  value: string,
): value is SoftwareTypeFilter {
  return (
    value === "all"
    || value === "application"
    || value === "package"
  );
}


function isSoftwareSort(
  value: string,
): value is SoftwareSort {
  return (
    value === "name"
    || value === "machines"
    || value === "exposures"
  );
}


function displayVendor(
  item: SoftwareSummary,
): string {
  if (
    item.component_type
    === "package"
  ) {
    return (
      item.ecosystem
      ?? "Non renseigné"
    );
  }

  return (
    item.vendor
    ?? "Non renseigné"
  );
}


function displayVersion(
  value: string | null,
): string {
  if (
    value === null
    || value.trim() === ""
  ) {
    return "Non renseignée";
  }

  return value;
}


type SoftwareStatisticProps = {
  icon: LucideIcon;
  value: number;
  label: string;
};


function SoftwareStatistic({
  icon: Icon,
  value,
  label,
}: SoftwareStatisticProps) {
  return (
    <div className="software-statistic">
      <span className="software-statistic__icon">
        <Icon
          size={17}
          strokeWidth={1.8}
        />
      </span>

      <div className="software-statistic__content">
        <strong>
          {value}
        </strong>

        <span>
          {label}
        </span>
      </div>
    </div>
  );
}


export function SoftwarePage() {
  const [
    software,
    setSoftware,
  ] = useState<
    SoftwareSummary[]
  >([]);

  const [
    search,
    setSearch,
  ] = useState("");

  const [
    typeFilter,
    setTypeFilter,
  ] = useState<
    SoftwareTypeFilter
  >("all");

  const [
    sort,
    setSort,
  ] = useState<
    SoftwareSort
  >("name");

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

    async function loadSoftware() {
      setIsLoading(true);
      setError(null);

      try {
        const response =
          await getSoftware();

        if (!cancelled) {
          setSoftware(
            response.items,
          );
        }
      } catch (caughtError) {
        if (!cancelled) {
          if (
            caughtError
            instanceof Error
          ) {
            setError(
              caughtError.message,
            );
          } else {
            setError(
              "Une erreur inattendue "
              + "est survenue.",
            );
          }
        }
      } finally {
        if (!cancelled) {
          setIsLoading(
            false,
          );
        }
      }
    }

    void loadSoftware();

    return () => {
      cancelled = true;
    };
  }, []);


  const visibleSoftware =
    useMemo(() => {
      const searchValue =
        search
          .trim()
          .toLowerCase();

      const filtered =
        software.filter(
          (item) => {
            if (
              typeFilter !== "all"
              && item.component_type
                !== typeFilter
            ) {
              return false;
            }

            if (!searchValue) {
              return true;
            }

            const searchable = [
              item.name,
              item.version,
              item.vendor,
              item.ecosystem,
              item.component_type,
            ]
              .filter(
                (
                  value,
                ): value is string => (
                  typeof value
                  === "string"
                ),
              )
              .join(" ")
              .toLowerCase();

            return searchable.includes(
              searchValue,
            );
          },
        );

      const result = [
        ...filtered,
      ];

      result.sort(
        (
          left,
          right,
        ) => {
          if (
            sort === "machines"
          ) {
            return (
              right.machine_count
              - left.machine_count
            );
          }

          if (
            sort === "exposures"
          ) {
            return (
              right.exposure_count
              - left.exposure_count
            );
          }

          return (
            left.name.localeCompare(
              right.name,
              "fr",
              {
                sensitivity: "base",
              },
            )
          );
        },
      );

      return result;
    }, [
      software,
      search,
      typeFilter,
      sort,
    ]);


  const applicationCount =
    useMemo(
      () => (
        software.filter(
          (item) => (
            item.component_type
            === "application"
          ),
        ).length
      ),
      [
        software,
      ],
    );


  const packageCount =
    useMemo(
      () => (
        software.filter(
          (item) => (
            item.component_type
            === "package"
          ),
        ).length
      ),
      [
        software,
      ],
    );


  function handleTypeFilterChange(
    value: string,
  ) {
    if (
      isSoftwareTypeFilter(
        value,
      )
    ) {
      setTypeFilter(
        value,
      );
    }
  }


  function handleSortChange(
    value: string,
  ) {
    if (
      isSoftwareSort(
        value,
      )
    ) {
      setSort(
        value,
      );
    }
  }


  return (
    <main className="security-page">
      <header className="security-page-header">
        <div>
          <h1>
            Logiciels
          </h1>

          <p>
            Vue agrégée des composants
            logiciels inventoriés sur les
            machines de l'organisation.
          </p>
        </div>
      </header>

      {isLoading && (
        <Card>
          <div className="loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Chargement des logiciels...
            </span>
          </div>
        </Card>
      )}

      {error && (
        <Card>
          <div className="error-state">
            <strong>
              Logiciels indisponibles
            </strong>

            <span>
              {error}
            </span>
          </div>
        </Card>
      )}

      {!isLoading
        && !error
        && software.length === 0 && (
          <Card className="software-empty-panel">
            <PackageOpen
              size={24}
              strokeWidth={1.6}
            />

            <strong>
              Aucun logiciel inventorié
            </strong>

            <p>
              Aucun composant logiciel
              n'est disponible pour cette
              organisation.
            </p>
          </Card>
        )}

      {!isLoading
        && !error
        && software.length > 0 && (
          <>
            <section
              className="software-statistics"
              aria-label="Résumé des logiciels"
            >
              <SoftwareStatistic
                icon={Boxes}
                value={
                  software.length
                }
                label="Logiciels agrégés"
              />

              <SoftwareStatistic
                icon={AppWindow}
                value={
                  applicationCount
                }
                label="Applications"
              />

              <SoftwareStatistic
                icon={Package}
                value={
                  packageCount
                }
                label="Packages"
              />
            </section>

            <section className="software-controls">
              <div className="software-search">
                <Search
                  size={15}
                  strokeWidth={1.8}
                  aria-hidden="true"
                />

                <Input
                  type="search"
                  placeholder="Rechercher un logiciel..."
                  aria-label="Rechercher un logiciel"
                  value={search}
                  onChange={(
                    event,
                  ) => {
                    setSearch(
                      event.target.value,
                    );
                  }}
                />
              </div>

              <div className="software-filters">
                <label className="software-filter">
                  <span>
                    Type
                  </span>

                  <select
                    value={
                      typeFilter
                    }
                    onChange={(
                      event,
                    ) => {
                      handleTypeFilterChange(
                        event.target.value,
                      );
                    }}
                  >
                    <option value="all">
                      Tous
                    </option>

                    <option value="application">
                      Applications
                    </option>

                    <option value="package">
                      Packages
                    </option>
                  </select>
                </label>

                <label className="software-filter">
                  <span>
                    Trier par
                  </span>

                  <select
                    value={
                      sort
                    }
                    onChange={(
                      event,
                    ) => {
                      handleSortChange(
                        event.target.value,
                      );
                    }}
                  >
                    <option value="name">
                      Nom
                    </option>

                    <option value="machines">
                      Machines
                    </option>

                    <option value="exposures">
                      Expositions
                    </option>
                  </select>
                </label>
              </div>
            </section>

            <div className="software-results-meta">
              <span>
                {
                  visibleSoftware.length
                }
                {" "}
                résultat
                {
                  visibleSoftware.length
                  !== 1
                    ? "s"
                    : ""
                }
              </span>
            </div>

            {visibleSoftware.length === 0 ? (
              <Card className="software-empty-panel">
                <Search
                  size={22}
                  strokeWidth={1.6}
                />

                <strong>
                  Aucun résultat
                </strong>

                <p>
                  Aucun logiciel ne
                  correspond aux filtres
                  sélectionnés.
                </p>
              </Card>
            ) : (
              <Table className="software-table">
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

                    <th className="table-number">
                      Machines
                    </th>

                    <th className="table-number">
                      Expositions
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {visibleSoftware.map(
                    (
                      item,
                      index,
                    ) => (
                      <tr
                        key={
                          [
                            item.component_type,
                            item.name,
                            item.version
                              ?? "",
                            item.vendor
                              ?? "",
                            item.ecosystem
                              ?? "",
                            String(
                              index,
                            ),
                          ].join(":")
                        }
                      >
                        <td>
                          <span
                            className={
                              (
                                "software-type "
                                + "software-type--"
                                + item.component_type
                              )
                            }
                          >
                            {item.component_type
                              === "application" ? (
                                <AppWindow
                                  size={11}
                                  strokeWidth={1.8}
                                />
                              ) : (
                                <Package
                                  size={11}
                                  strokeWidth={1.8}
                                />
                              )}

                            <span>
                              {
                                item.component_type
                              }
                            </span>
                          </span>
                        </td>

                        <td>
                          <div className="software-name-cell">
                            <span className="software-row-icon">
                              {item.component_type
                                === "application" ? (
                                  <AppWindow
                                    size={14}
                                    strokeWidth={1.8}
                                  />
                                ) : (
                                  <Package
                                    size={14}
                                    strokeWidth={1.8}
                                  />
                                )}
                            </span>

                            <strong className="software-name">
                              {
                                item.name
                              }
                            </strong>
                          </div>
                        </td>

                        <td>
                          <span className="software-version">
                            {displayVersion(
                              item.version,
                            )}
                          </span>
                        </td>

                        <td>
                          <span className="software-vendor">
                            {displayVendor(
                              item,
                            )}
                          </span>
                        </td>

                        <td className="table-number">
                          <span className="software-machine-count">
                            {
                              item.machine_count
                            }
                          </span>
                        </td>

                        <td className="table-number">
                          {item.exposure_count > 0 ? (
                            <span className="software-exposure-active">
                              <ShieldAlert
                                size={11}
                                strokeWidth={1.8}
                              />

                              {
                                item.exposure_count
                              }
                            </span>
                          ) : (
                            <span className="software-exposure-empty">
                              0
                            </span>
                          )}
                        </td>
                      </tr>
                    ),
                  )}
                </tbody>
              </Table>
            )}
          </>
        )}
    </main>
  );
}