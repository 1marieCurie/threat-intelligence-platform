import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  BadgeCheck,
  Search,
  ShieldCheck,
  ShieldOff,
  TriangleAlert,
  Zap,
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
  getVulnerabilities,
} from "../../lib/api";

import type {
  VulnerabilitySummary,
} from "../../types/vulnerability";

import "./vulnerabilities.css";


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


type VulnerabilityStatisticProps = {
  icon: LucideIcon;
  value: number;
  label: string;
  tone?:
    | "default"
    | "success"
    | "critical";
};


function VulnerabilityStatistic({
  icon: Icon,
  value,
  label,
  tone = "default",
}: VulnerabilityStatisticProps) {
  return (
    <div
      className={
        "vulnerability-statistic "
        + `vulnerability-statistic--${tone}`
      }
    >
      <span className="vulnerability-statistic__icon">
        <Icon
          size={17}
          strokeWidth={1.8}
        />
      </span>

      <div className="vulnerability-statistic__content">
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


function priorityClass(
  value: string | null,
): string {
  return (
    "vulnerability-priority-tag "
    + "vulnerability-priority-tag--"
    + (
      value
      ?? "unknown"
    ).toLowerCase()
  );
}


function severityClass(
  value: string | null,
): string {
  return (
    "vulnerability-severity-tag "
    + "vulnerability-severity-tag--"
    + (
      value
      ?? "unknown"
    ).toLowerCase()
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
          <Card className="vulnerability-empty-panel">
            <ShieldCheck
              size={25}
              strokeWidth={1.6}
            />

            <strong>
              Aucune exposition détectée
            </strong>

            <p>
              Aucune vulnérabilité n'est
              actuellement associée aux
              composants inventoriés de
              cette organisation.
            </p>
          </Card>
        )}

      {!isLoading
        && !error
        && vulnerabilities.length
          > 0 && (
          <>
            <section
              className="vulnerability-statistics"
              aria-label="Résumé des vulnérabilités"
            >
              <VulnerabilityStatistic
                icon={ShieldOff}
                value={
                  vulnerabilities.length
                }
                label="Vulnérabilités"
              />

              <VulnerabilityStatistic
                icon={BadgeCheck}
                value={
                  confirmedCount
                }
                label="Confirmed"
                tone="success"
              />

              <VulnerabilityStatistic
                icon={TriangleAlert}
                value={
                  criticalCount
                }
                label="Critiques"
                tone={
                  criticalCount > 0
                    ? "critical"
                    : "default"
                }
              />

              <VulnerabilityStatistic
                icon={Zap}
                value={
                  kevCount
                }
                label="KEV"
                tone={
                  kevCount > 0
                    ? "critical"
                    : "default"
                }
              />
            </section>

            <section className="vulnerability-controls">
              <div className="vulnerability-search">
                <Search
                  size={15}
                  strokeWidth={1.8}
                  aria-hidden="true"
                />

                <Input
                  type="search"
                  placeholder="Rechercher CVE, GHSA ou CWE..."
                  aria-label="Rechercher une vulnérabilité"
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

              <div className="vulnerability-filters">
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

                <label className="vulnerability-kev-toggle">
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

                  <span className="vulnerability-kev-toggle__control">
                    <span />
                  </span>

                  <span className="vulnerability-kev-toggle__label">
                    KEV uniquement
                  </span>
                </label>
              </div>
            </section>

            <div className="vulnerability-results-meta">
              <span>
                {
                  visibleVulnerabilities.length
                }
                {" "}
                vulnérabilité
                {
                  visibleVulnerabilities.length
                  !== 1
                    ? "s"
                    : ""
                }
              </span>
            </div>

            {visibleVulnerabilities.length
              === 0 ? (
              <Card className="vulnerability-empty-panel">
                <Search
                  size={22}
                  strokeWidth={1.6}
                />

                <strong>
                  Aucun résultat
                </strong>

                <p>
                  Aucune vulnérabilité ne
                  correspond aux filtres
                  sélectionnés.
                </p>
              </Card>
            ) : (
              <Table className="vulnerability-table">
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
                          <div className="vulnerability-primary-cell">
                            <span
                              className={
                                item.is_kev
                                  ? (
                                    "vulnerability-row-icon "
                                    + "vulnerability-row-icon--critical"
                                  )
                                  : "vulnerability-row-icon"
                              }
                            >
                              <ShieldOff
                                size={14}
                                strokeWidth={1.8}
                              />
                            </span>

                            <div>
                              <strong className="vulnerability-id">
                                {displayIdentifier(
                                  item,
                                )}
                              </strong>

                              <span className="vulnerability-short-id">
                                {
                                  item
                                    .canonical_vulnerability_id
                                    .slice(
                                      0,
                                      8,
                                    )
                                }
                              </span>
                            </div>
                          </div>
                        </td>

                        <td>
                          <span
                            className={
                              severityClass(
                                item.severity,
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
                              priorityClass(
                                item.priority,
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
                          <strong className="vulnerability-score">
                            {displayScore(
                              item.cvss_score,
                            )}
                          </strong>

                          {item.cvss_version && (
                            <span className="vulnerability-score-detail">
                              CVSS{" "}
                              {
                                item.cvss_version
                              }
                            </span>
                          )}
                        </td>

                        <td>
                          <span className="vulnerability-epss">
                            {displayEpss(
                              item.epss_score,
                            )}
                          </span>
                        </td>

                        <td>
                          <div className="vulnerability-applicability">
                            <span className="vulnerability-applicability__confirmed">
                              <BadgeCheck
                                size={11}
                                strokeWidth={1.8}
                              />

                              {
                                item
                                  .confirmed_exposure_count
                              }
                            </span>

                            <span className="vulnerability-applicability__potential">
                              {
                                item
                                  .potential_exposure_count
                              }
                              {" "}
                              potential
                            </span>
                          </div>
                        </td>

                        <td className="table-number">
                          <strong className="vulnerability-table-count">
                            {
                              item.machine_count
                            }
                          </strong>
                        </td>

                        <td className="table-number">
                          <strong className="vulnerability-table-count">
                            {
                              item.component_count
                            }
                          </strong>
                        </td>

                        <td>
                          {item.cwe_ids.length
                            === 0 ? (
                            <span className="vulnerability-muted">
                              —
                            </span>
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
                              <Zap
                                size={11}
                                strokeWidth={1.9}
                              />

                              KEV
                            </span>
                          ) : (
                            <span className="vulnerability-muted">
                              —
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