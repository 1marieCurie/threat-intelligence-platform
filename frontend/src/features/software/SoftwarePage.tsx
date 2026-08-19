import {
  useEffect,
  useMemo,
  useState,
} from "react";

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
          <Card>
            <div className="software-empty-state">
              <strong>
                Aucun logiciel inventorié
              </strong>

              <p>
                Aucun composant logiciel
                n'est disponible pour cette
                organisation.
              </p>
            </div>
          </Card>
        )}

      {!isLoading
        && !error
        && software.length > 0 && (
          <>
            <section className="software-summary-grid">
              <Card>
                <span className="software-summary-label">
                  Logiciels agrégés
                </span>

                <strong className="software-summary-value">
                  {software.length}
                </strong>
              </Card>

              <Card>
                <span className="software-summary-label">
                  Applications
                </span>

                <strong className="software-summary-value">
                  {applicationCount}
                </strong>
              </Card>

              <Card>
                <span className="software-summary-label">
                  Packages
                </span>

                <strong className="software-summary-value">
                  {packageCount}
                </strong>
              </Card>
            </section>

            <Card>
              <div className="software-toolbar">
                <div className="software-search">
                  <Input
                    type="search"
                    placeholder={
                      "Rechercher un logiciel..."
                    }
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
            </Card>

            {visibleSoftware.length === 0 ? (
              <Card>
                <div className="software-empty-state">
                  <strong>
                    Aucun résultat
                  </strong>

                  <p>
                    Aucun logiciel ne
                    correspond aux filtres
                    sélectionnés.
                  </p>
                </div>
              </Card>
            ) : (
              <Table>
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
                                "component-type "
                                + "component-type--"
                                + item.component_type
                              )
                            }
                          >
                            {
                              item.component_type
                            }
                          </span>
                        </td>

                        <td>
                          <strong className="software-name">
                            {
                              item.name
                            }
                          </strong>
                        </td>

                        <td>
                          {displayVersion(
                            item.version,
                          )}
                        </td>

                        <td>
                          {displayVendor(
                            item,
                          )}
                        </td>

                        <td className="table-number">
                          {
                            item.machine_count
                          }
                        </td>

                        <td className="table-number">
                          <span
                            className={
                              item.exposure_count
                              > 0
                                ? (
                                  "software-exposure-count "
                                  + "software-exposure-count--active"
                                )
                                : (
                                  "software-exposure-count"
                                )
                            }
                          >
                            {
                              item.exposure_count
                            }
                          </span>
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