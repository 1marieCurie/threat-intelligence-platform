import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Link,
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
  getVulnerabilities,
} from "../../lib/api";

import type {
  VulnerabilitySummary,
} from "../../types/vulnerability";


type PriorityFilter =
  | "all"
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";


type ApplicabilityFilter =
  | "all"
  | "confirmed"
  | "potential";


type VulnerabilitySort =
  | "priority"
  | "identifier"
  | "cvss"
  | "epss"
  | "machines";


const PRIORITY_RANK: Record<
  string,
  number
> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};


function isPriorityFilter(
  value: string,
): value is PriorityFilter {
  return (
    value === "all"
    || value === "LOW"
    || value === "MEDIUM"
    || value === "HIGH"
    || value === "CRITICAL"
  );
}


function isApplicabilityFilter(
  value: string,
): value is ApplicabilityFilter {
  return (
    value === "all"
    || value === "confirmed"
    || value === "potential"
  );
}


function isVulnerabilitySort(
  value: string,
): value is VulnerabilitySort {
  return (
    value === "priority"
    || value === "identifier"
    || value === "cvss"
    || value === "epss"
    || value === "machines"
  );
}


function displayScore(
  value: number | null,
  digits = 1,
): string {
  if (
    value === null
  ) {
    return "—";
  }

  return value.toFixed(
    digits,
  );
}


function displayEpss(
  value: number | null,
): string {
  if (
    value === null
  ) {
    return "—";
  }

  return (
    (
      value
      * 100
    ).toFixed(1)
    + " %"
  );
}


function displayIdentifier(
  vulnerability: VulnerabilitySummary,
): string {
  return (
    vulnerability.primary_identifier
    ?? vulnerability
      .canonical_vulnerability_id
      .slice(
        0,
        8,
      )
  );
}


export function VulnerabilitiesPage() {
  const [
    vulnerabilities,
    setVulnerabilities,
  ] = useState<
    VulnerabilitySummary[]
  >([]);

  const [
    search,
    setSearch,
  ] = useState("");

  const [
    priorityFilter,
    setPriorityFilter,
  ] = useState<
    PriorityFilter
  >("all");

  const [
    applicabilityFilter,
    setApplicabilityFilter,
  ] = useState<
    ApplicabilityFilter
  >("all");

  const [
    kevOnly,
    setKevOnly,
  ] = useState(false);

  const [
    sort,
    setSort,
  ] = useState<
    VulnerabilitySort
  >("priority");

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

    async function loadVulnerabilities() {
      setIsLoading(true);
      setError(null);

      try {
        const response =
          await getVulnerabilities();

        if (!cancelled) {
          setVulnerabilities(
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

    void loadVulnerabilities();

    return () => {
      cancelled = true;
    };
  }, []);


  const visibleVulnerabilities =
    useMemo(() => {
      const searchValue =
        search
          .trim()
          .toLowerCase();

      const filtered =
        vulnerabilities.filter(
          (item) => {
            if (
              priorityFilter
              !== "all"
              && item.priority
              !== priorityFilter
            ) {
              return false;
            }

            if (
              applicabilityFilter
              === "confirmed"
              && item
                .confirmed_exposure_count
                === 0
            ) {
              return false;
            }

            if (
              applicabilityFilter
              === "potential"
              && item
                .potential_exposure_count
                === 0
            ) {
              return false;
            }

            if (
              kevOnly
              && !item.is_kev
            ) {
              return false;
            }

            if (!searchValue) {
              return true;
            }

            const searchable = [
              item.primary_identifier,
              item.severity,
              item.priority,
              ...item.cwe_ids,
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
            sort === "identifier"
          ) {
            return (
              displayIdentifier(
                left,
              )
              .localeCompare(
                displayIdentifier(
                  right,
                ),
                "fr",
              )
            );
          }

          if (
            sort === "cvss"
          ) {
            return (
              (
                right.cvss_score
                ?? -1
              )
              - (
                left.cvss_score
                ?? -1
              )
            );
          }

          if (
            sort === "epss"
          ) {
            return (
              (
                right.epss_score
                ?? -1
              )
              - (
                left.epss_score
                ?? -1
              )
            );
          }

          if (
            sort === "machines"
          ) {
            return (
              right.machine_count
              - left.machine_count
            );
          }

          const rightRank =
            right.priority
              ? (
                PRIORITY_RANK[
                  right.priority
                ]
                ?? 0
              )
              : 0;

          const leftRank =
            left.priority
              ? (
                PRIORITY_RANK[
                  left.priority
                ]
                ?? 0
              )
              : 0;

          return (
            rightRank
            - leftRank
          );
        },
      );

      return result;
    }, [
      vulnerabilities,
      search,
      priorityFilter,
      applicabilityFilter,
      kevOnly,
      sort,
    ]);


  const criticalCount =
    useMemo(
      () => (
        vulnerabilities.filter(
          (item) => (
            item.priority
            === "CRITICAL"
          ),
        ).length
      ),
      [
        vulnerabilities,
      ],
    );


  const kevCount =
    useMemo(
      () => (
        vulnerabilities.filter(
          (item) => (
            item.is_kev
          ),
        ).length
      ),
      [
        vulnerabilities,
      ],
    );


  const confirmedCount =
    useMemo(
      () => (
        vulnerabilities.filter(
          (item) => (
            item
              .confirmed_exposure_count
              > 0
          ),
        ).length
      ),
      [
        vulnerabilities,
      ],
    );


  function handlePriorityChange(
    value: string,
  ) {
    if (
      isPriorityFilter(
        value,
      )
    ) {
      setPriorityFilter(
        value,
      );
    }
  }


  function handleApplicabilityChange(
    value: string,
  ) {
    if (
      isApplicabilityFilter(
        value,
      )
    ) {
      setApplicabilityFilter(
        value,
      );
    }
  }


  function handleSortChange(
    value: string,
  ) {
    if (
      isVulnerabilitySort(
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
            Vulnérabilités
          </h1>

          <p>
            Vue agrégée des vulnérabilités
            affectant les machines et
            logiciels de l'organisation.
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
              Chargement des vulnérabilités...
            </span>
          </div>
        </Card>
      )}

      {error && (
        <Card>
          <div className="error-state">
            <strong>
              Vulnérabilités indisponibles
            </strong>

            <span>
              {error}
            </span>
          </div>
        </Card>
      )}

      {!isLoading
        && !error
        && vulnerabilities.length
          === 0 && (
          <Card>
            <div className="vulnerability-empty-state">
              <div className="vulnerability-empty-icon">
                ✓
              </div>

              <strong>
                Aucune exposition détectée
              </strong>

              <p>
                Aucune vulnérabilité n'est
                actuellement associée aux
                composants inventoriés de
                cette organisation.
              </p>
            </div>
          </Card>
        )}

      {!isLoading
        && !error
        && vulnerabilities.length
          > 0 && (
          <>
            <section className="vulnerability-summary-grid">
              <Card>
                <span className="vulnerability-summary-label">
                  Vulnérabilités
                </span>

                <strong className="vulnerability-summary-value">
                  {
                    vulnerabilities.length
                  }
                </strong>
              </Card>

              <Card>
                <span className="vulnerability-summary-label">
                  Confirmed
                </span>

                <strong className="vulnerability-summary-value">
                  {
                    confirmedCount
                  }
                </strong>
              </Card>

              <Card>
                <span className="vulnerability-summary-label">
                  Critiques
                </span>

                <strong className="vulnerability-summary-value">
                  {
                    criticalCount
                  }
                </strong>
              </Card>

              <Card>
                <span className="vulnerability-summary-label">
                  KEV
                </span>

                <strong className="vulnerability-summary-value">
                  {
                    kevCount
                  }
                </strong>
              </Card>
            </section>

            <Card>
              <div className="vulnerability-toolbar">
                <div className="vulnerability-search">
                  <Input
                    type="search"
                    placeholder={
                      "Rechercher CVE, GHSA ou CWE..."
                    }
                    value={
                      search
                    }
                    onChange={(
                      event,
                    ) => {
                      setSearch(
                        event
                          .target
                          .value,
                      );
                    }}
                  />
                </div>

                <label className="vulnerability-filter">
                  <span>
                    Priorité
                  </span>

                  <select
                    value={
                      priorityFilter
                    }
                    onChange={(
                      event,
                    ) => {
                      handlePriorityChange(
                        event
                          .target
                          .value,
                      );
                    }}
                  >
                    <option value="all">
                      Toutes
                    </option>

                    <option value="CRITICAL">
                      Critical
                    </option>

                    <option value="HIGH">
                      High
                    </option>

                    <option value="MEDIUM">
                      Medium
                    </option>

                    <option value="LOW">
                      Low
                    </option>
                  </select>
                </label>

                <label className="vulnerability-filter">
                  <span>
                    Applicabilité
                  </span>

                  <select
                    value={
                      applicabilityFilter
                    }
                    onChange={(
                      event,
                    ) => {
                      handleApplicabilityChange(
                        event
                          .target
                          .value,
                      );
                    }}
                  >
                    <option value="all">
                      Toutes
                    </option>

                    <option value="confirmed">
                      Confirmed
                    </option>

                    <option value="potential">
                      Potential
                    </option>
                  </select>
                </label>

                <label className="vulnerability-filter">
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
                        event
                          .target
                          .value,
                      );
                    }}
                  >
                    <option value="priority">
                      Priorité
                    </option>

                    <option value="identifier">
                      Identifiant
                    </option>

                    <option value="cvss">
                      CVSS
                    </option>

                    <option value="epss">
                      EPSS
                    </option>

                    <option value="machines">
                      Machines
                    </option>
                  </select>
                </label>

                <label className="vulnerability-kev-filter">
                  <input
                    type="checkbox"
                    checked={
                      kevOnly
                    }
                    onChange={(
                      event,
                    ) => {
                      setKevOnly(
                        event
                          .target
                          .checked,
                      );
                    }}
                  />

                  <span>
                    KEV uniquement
                  </span>
                </label>
              </div>
            </Card>

            {visibleVulnerabilities.length
              === 0 ? (
              <Card>
                <div className="vulnerability-empty-state">
                  <strong>
                    Aucun résultat
                  </strong>

                  <p>
                    Aucune vulnérabilité ne
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
                      Vulnérabilité
                    </th>

                    <th>
                      Severity
                    </th>

                    <th>
                      Priorité
                    </th>

                    <th>
                      CVSS
                    </th>

                    <th>
                      EPSS
                    </th>

                    <th>
                      Applicabilité
                    </th>

                    <th className="table-number">
                      Machines
                    </th>

                    <th className="table-number">
                      Composants
                    </th>

                    <th>
                      CWE
                    </th>

                    <th>
                      KEV
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {visibleVulnerabilities.map(
                    (
                      item,
                    ) => (
                      <tr
                        key={
                          item
                            .canonical_vulnerability_id
                        }
                      >
                        <td>
                          <Link
                            to={
                              (
                                "/vulnerabilites/"
                                + item
                                  .canonical_vulnerability_id
                              )
                            }
                            aria-label={
                              (
                                "Ouvrir la vulnérabilité "
                                + displayIdentifier(
                                  item,
                                )
                              )
                            }
                          >
                            <strong className="vulnerability-id">
                              {displayIdentifier(
                                item,
                              )}
                            </strong>
                          </Link>
                        </td>

                        <td>
                          <span
                            className={
                              (
                                "vulnerability-severity "
                                + "vulnerability-severity--"
                                + (
                                  item.severity
                                  ?? "unknown"
                                )
                                  .toLowerCase()
                              )
                            }
                          >
                            {
                              item.severity
                              ?? "—"
                            }
                          </span>
                        </td>

                        <td>
                          <span
                            className={
                              (
                                "vulnerability-priority "
                                + "vulnerability-priority--"
                                + (
                                  item.priority
                                  ?? "unknown"
                                )
                                  .toLowerCase()
                              )
                            }
                          >
                            {
                              item.priority
                              ?? "—"
                            }
                          </span>
                        </td>

                        <td>
                          <strong>
                            {displayScore(
                              item.cvss_score,
                            )}
                          </strong>

                          {item.cvss_version && (
                            <div className="table-secondary">
                              CVSS {
                                item.cvss_version
                              }
                            </div>
                          )}
                        </td>

                        <td>
                          {displayEpss(
                            item.epss_score,
                          )}
                        </td>

                        <td>
                          <div className="vulnerability-applicability">
                            <span>
                              Confirmed:
                              {" "}
                              {
                                item
                                  .confirmed_exposure_count
                              }
                            </span>

                            <span>
                              Potential:
                              {" "}
                              {
                                item
                                  .potential_exposure_count
                              }
                            </span>
                          </div>
                        </td>

                        <td className="table-number">
                          {
                            item.machine_count
                          }
                        </td>

                        <td className="table-number">
                          {
                            item.component_count
                          }
                        </td>

                        <td>
                          {item.cwe_ids.length
                            === 0 ? (
                            "—"
                          ) : (
                            <div className="vulnerability-cwe-list">
                              {item.cwe_ids
                                .slice(
                                  0,
                                  3,
                                )
                                .map(
                                  (
                                    cweId,
                                  ) => (
                                    <span
                                      key={
                                        cweId
                                      }
                                    >
                                      {
                                        cweId
                                      }
                                    </span>
                                  ),
                                )}

                              {item.cwe_ids.length
                                > 3 && (
                                <span>
                                  +{
                                    item
                                      .cwe_ids
                                      .length
                                    - 3
                                  }
                                </span>
                              )}
                            </div>
                          )}
                        </td>

                        <td>
                          {item.is_kev ? (
                            <span className="vulnerability-kev">
                              KEV
                            </span>
                          ) : (
                            "—"
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