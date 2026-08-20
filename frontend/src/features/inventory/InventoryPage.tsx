import {
  useEffect,
  useState,
} from "react";

import {
  Button,
} from "../../components/ui/Button";

import {
  Card,
} from "../../components/ui/Card";

import {
  getWindowsInventoryScript,
  importInventory,
} from "../../lib/api";

import type {
  InventoryImportResult,
  MachineInventoryPayload,
} from "../../types/inventory";

import "./InventoryPage.css";


const WINDOWS_COMMAND = (
  "powershell.exe "
  + "-NoProfile "
  + "-ExecutionPolicy Bypass "
  + "-File \".\\collect_inventory.ps1\" "
  + "-OutputPath \".\\inventory.json\""
);


function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object"
    && value !== null
    && !Array.isArray(value)
  );
}


function isNonEmptyString(
  value: unknown,
): value is string {
  return (
    typeof value === "string"
    && value.trim().length > 0
  );
}


function isNullableString(
  value: unknown,
): value is string | null {
  return (
    value === null
    || typeof value === "string"
  );
}


function isUuid(
  value: unknown,
): value is string {
  if (
    !isNonEmptyString(value)
  ) {
    return false;
  }

  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  if (
    !uuidPattern.test(value)
  ) {
    return false;
  }

  return (
    value
      .replaceAll("-", "")
      .toLowerCase()
    !== "00000000000000000000000000000000"
  );
}


function isValidDateTime(
  value: unknown,
): value is string {
  if (
    !isNonEmptyString(value)
  ) {
    return false;
  }

  return !Number.isNaN(
    Date.parse(value),
  );
}


function isInventoryComponent(
  value: unknown,
): boolean {
  if (
    !isRecord(value)
  ) {
    return false;
  }

  if (
    value.component_type
    === "application"
  ) {
    return (
      isNonEmptyString(
        value.name,
      )
      && isNullableString(
        value.version,
      )
      && isNullableString(
        value.vendor,
      )
      && isNonEmptyString(
        value.external_id,
      )
      && value.detected_by
        === "windows_registry_uninstall"
    );
  }

  if (
    value.component_type
    === "package"
  ) {
    if (
      value.ecosystem
      !== "pypi"
      && value.ecosystem
      !== "npm"
    ) {
      return false;
    }

    if (
      value.ecosystem
      === "pypi"
      && value.detected_by
      !== "pip_global"
    ) {
      return false;
    }

    if (
      value.ecosystem
      === "npm"
      && value.detected_by
      !== "npm_global"
    ) {
      return false;
    }

    return (
      isNonEmptyString(
        value.package_name,
      )
      && isNonEmptyString(
        value.version,
      )
      && value.scope
        === "global"
    );
  }

  return false;
}


function isMachineInventoryPayload(
  value: unknown,
): value is MachineInventoryPayload {
  if (
    !isRecord(value)
  ) {
    return false;
  }

  if (
    value.schema_version
    !== "inventory/v1"
  ) {
    return false;
  }

  if (
    !isUuid(
      value.inventory_id,
    )
  ) {
    return false;
  }

  if (
    !isValidDateTime(
      value.collected_at,
    )
  ) {
    return false;
  }

  if (
    !isRecord(
      value.agent,
    )
  ) {
    return false;
  }

  if (
    !isNonEmptyString(
      value.agent.name,
    )
    || !isNonEmptyString(
      value.agent.version,
    )
  ) {
    return false;
  }

  if (
    !isRecord(
      value.machine,
    )
  ) {
    return false;
  }

  if (
    !isUuid(
      value.machine.machine_uid,
    )
    || !isNonEmptyString(
      value.machine.hostname,
    )
    || !isNonEmptyString(
      value.machine.os_name,
    )
    || !isNonEmptyString(
      value.machine.os_version,
    )
    || !isNonEmptyString(
      value.machine.architecture,
    )
  ) {
    return false;
  }

  if (
    !Array.isArray(
      value.components,
    )
  ) {
    return false;
  }

  return value.components.every(
    (
      component: unknown,
    ) => (
      isInventoryComponent(
        component,
      )
    ),
  );
}


function parseInventoryFile(
  content: string,
): MachineInventoryPayload {
  let parsedJson: unknown;

  try {
    parsedJson =
      JSON.parse(content);
  } catch {
    throw new Error(
      "Le fichier sélectionné "
      + "n'est pas un JSON valide.",
    );
  }

  if (
    !isRecord(parsedJson)
  ) {
    throw new Error(
      "L'inventaire doit contenir "
      + "un objet JSON.",
    );
  }

  if (
    parsedJson.schema_version
    !== "inventory/v1"
  ) {
    throw new Error(
      "Le fichier doit utiliser "
      + "le schéma inventory/v1.",
    );
  }

  if (
    !isUuid(
      parsedJson.inventory_id,
    )
  ) {
    throw new Error(
      "L'identifiant inventory_id "
      + "est invalide.",
    );
  }

  if (
    !isValidDateTime(
      parsedJson.collected_at,
    )
  ) {
    throw new Error(
      "La date collected_at "
      + "est invalide.",
    );
  }

  if (
    !isRecord(
      parsedJson.agent,
    )
  ) {
    throw new Error(
      "Les informations de l'agent "
      + "sont invalides.",
    );
  }

  if (
    !isNonEmptyString(
      parsedJson.agent.name,
    )
    || !isNonEmptyString(
      parsedJson.agent.version,
    )
  ) {
    throw new Error(
      "Les informations de l'agent "
      + "sont invalides.",
    );
  }

  if (
    !isRecord(
      parsedJson.machine,
    )
  ) {
    throw new Error(
      "Les informations de la machine "
      + "sont absentes.",
    );
  }

  if (
    !isUuid(
      parsedJson.machine.machine_uid,
    )
    || !isNonEmptyString(
      parsedJson.machine.hostname,
    )
    || !isNonEmptyString(
      parsedJson.machine.os_name,
    )
    || !isNonEmptyString(
      parsedJson.machine.os_version,
    )
    || !isNonEmptyString(
      parsedJson.machine.architecture,
    )
  ) {
    throw new Error(
      "Les informations de la machine "
      + "sont invalides.",
    );
  }

  if (
    !Array.isArray(
      parsedJson.components,
    )
  ) {
    throw new Error(
      "Le champ components "
      + "doit être un tableau.",
    );
  }

  if (
    !parsedJson.components.every(
      (
        component: unknown,
      ) => (
        isInventoryComponent(
          component,
        )
      ),
    )
  ) {
    throw new Error(
      "Un ou plusieurs composants "
      + "ne respectent pas "
      + "le contrat inventory/v1.",
    );
  }

  if (
    !isMachineInventoryPayload(
      parsedJson,
    )
  ) {
    throw new Error(
      "Le fichier ne respecte pas "
      + "le contrat inventory/v1.",
    );
  }

  return parsedJson;
}


function displayImportStatus(
  result: InventoryImportResult,
): string {
  if (
    result.status
    === "idempotent"
  ) {
    return (
      "Inventaire déjà importé"
    );
  }

  if (
    result.machine_created
  ) {
    return (
      "Nouvelle machine importée"
    );
  }

  return (
    "Inventaire mis à jour"
  );
}


export function InventoryPage() {
  const [
    script,
    setScript,
  ] = useState("");

  const [
    isScriptLoading,
    setIsScriptLoading,
  ] = useState(true);

  const [
    scriptError,
    setScriptError,
  ] = useState<string | null>(
    null,
  );

  const [
    scriptCopied,
    setScriptCopied,
  ] = useState(false);

  const [
    commandCopied,
    setCommandCopied,
  ] = useState(false);

  const [
    selectedFile,
    setSelectedFile,
  ] = useState<File | null>(
    null,
  );

  const [
    inventory,
    setInventory,
  ] = useState<
    MachineInventoryPayload | null
  >(null);

  const [
    fileError,
    setFileError,
  ] = useState<string | null>(
    null,
  );

  const [
    isImporting,
    setIsImporting,
  ] = useState(false);

  const [
    importError,
    setImportError,
  ] = useState<string | null>(
    null,
  );

  const [
    importResult,
    setImportResult,
  ] = useState<
    InventoryImportResult | null
  >(null);


  useEffect(() => {
    let cancelled = false;

    async function loadScript() {
      setIsScriptLoading(
        true,
      );

      setScriptError(
        null,
      );

      try {
        const content =
          await getWindowsInventoryScript();

        if (
          !cancelled
        ) {
          setScript(
            content,
          );
        }
      } catch (
        caughtError
      ) {
        if (
          !cancelled
        ) {
          if (
            caughtError
            instanceof Error
          ) {
            setScriptError(
              caughtError.message,
            );
          } else {
            setScriptError(
              "Une erreur inattendue "
              + "est survenue.",
            );
          }
        }
      } finally {
        if (
          !cancelled
        ) {
          setIsScriptLoading(
            false,
          );
        }
      }
    }

    void loadScript();

    return () => {
      cancelled = true;
    };
  }, []);


  async function copyText(
    text: string,
  ): Promise<void> {
    if (
      !navigator.clipboard
    ) {
      throw new Error(
        "Le presse-papiers "
        + "n'est pas disponible.",
      );
    }

    await navigator.clipboard.writeText(
      text,
    );
  }


  async function handleCopyScript(
  ): Promise<void> {
    try {
      await copyText(
        script,
      );

      setScriptCopied(
        true,
      );

      window.setTimeout(
        () => {
          setScriptCopied(
            false,
          );
        },
        1800,
      );
    } catch {
      setScriptError(
        "Impossible de copier "
        + "le script.",
      );
    }
  }


  async function handleCopyCommand(
  ): Promise<void> {
    try {
      await copyText(
        WINDOWS_COMMAND,
      );

      setCommandCopied(
        true,
      );

      window.setTimeout(
        () => {
          setCommandCopied(
            false,
          );
        },
        1800,
      );
    } catch {
      setScriptError(
        "Impossible de copier "
        + "la commande.",
      );
    }
  }


  async function handleFileChange(
    file: File | null,
  ): Promise<void> {
    setSelectedFile(
      file,
    );

    setInventory(
      null,
    );

    setFileError(
      null,
    );

    setImportError(
      null,
    );

    setImportResult(
      null,
    );

    if (
      !file
    ) {
      return;
    }

    if (
      !file.name
        .toLowerCase()
        .endsWith(".json")
    ) {
      setFileError(
        "Sélectionnez un fichier "
        + "JSON généré par l'agent.",
      );

      return;
    }

    try {
      const content =
        await file.text();

      const parsedInventory =
        parseInventoryFile(
          content,
        );

      setInventory(
        parsedInventory,
      );
    } catch (
      caughtError
    ) {
      if (
        caughtError
        instanceof Error
      ) {
        setFileError(
          caughtError.message,
        );
      } else {
        setFileError(
          "Impossible de lire "
          + "ce fichier.",
        );
      }
    }
  }


  async function handleImport(
  ): Promise<void> {
    if (
      !inventory
    ) {
      return;
    }

    setIsImporting(
      true,
    );

    setImportError(
      null,
    );

    setImportResult(
      null,
    );

    try {
      const result =
        await importInventory(
          inventory,
        );

      setImportResult(
        result,
      );
    } catch (
      caughtError
    ) {
      if (
        caughtError
        instanceof Error
      ) {
        setImportError(
          caughtError.message,
        );
      } else {
        setImportError(
          "Une erreur inattendue "
          + "est survenue.",
        );
      }
    } finally {
      setIsImporting(
        false,
      );
    }
  }


  return (
    <main className="security-page">
      <header className="security-page-header">
        <div>
          <h1>
            Inventaires
          </h1>

          <p>
            Collectez les applications
            Windows ainsi que les packages
            PyPI et npm installés, puis
            importez le fichier JSON généré
            dans la plateforme.
          </p>
        </div>
      </header>

      <section className="inventory-flow-grid">
        <Card className="inventory-step-card">
          <span className="inventory-step-number">
            1
          </span>

          <strong>
            Copier le script
          </strong>

          <p>
            Enregistrez le collecteur
            PowerShell sur la machine
            Windows à inventorier.
          </p>
        </Card>

        <Card className="inventory-step-card">
          <span className="inventory-step-number">
            2
          </span>

          <strong>
            Exécuter la collecte
          </strong>

          <p>
            Lancez le script pour produire
            un fichier inventory.json.
          </p>
        </Card>

        <Card className="inventory-step-card">
          <span className="inventory-step-number">
            3
          </span>

          <strong>
            Importer le JSON
          </strong>

          <p>
            Sélectionnez le fichier généré
            et envoyez-le à la plateforme.
          </p>
        </Card>
      </section>

      <Card>
        <div className="inventory-section-header">
          <div>
            <span className="inventory-section-eyebrow">
              Étape 1
            </span>

            <h2>
              Collecteur Windows
            </h2>

            <p>
              Agent officiel inventory/v1.
              Il collecte les applications
              Windows, les packages Python
              globaux et les packages npm
              globaux disponibles.
            </p>
          </div>

          <span className="inventory-platform-badge">
            Windows
          </span>
        </div>

        {isScriptLoading && (
          <div className="loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Chargement du script...
            </span>
          </div>
        )}

        {scriptError && (
          <div className="error-state">
            <strong>
              Script indisponible
            </strong>

            <span>
              {scriptError}
            </span>
          </div>
        )}

        {!isScriptLoading
          && !scriptError
          && script && (
          <>
            <div className="inventory-code-toolbar">
              <div>
                <strong>
                  collect_inventory.ps1
                </strong>

                <span>
                  PowerShell
                </span>
              </div>

              <Button
                type="button"
                className="inventory-secondary-button"
                onClick={
                  handleCopyScript
                }
              >
                {scriptCopied
                  ? "Copié"
                  : "Copier le script"}
              </Button>
            </div>

            <pre className="inventory-code">
              <code>
                {script}
              </code>
            </pre>

            <div className="inventory-command-section">
              <div>
                <strong>
                  Commande d'exécution
                </strong>

                <p>
                  Après avoir enregistré le
                  script sous
                  collect_inventory.ps1,
                  exécutez cette commande
                  dans PowerShell.
                </p>
              </div>

              <div className="inventory-command">
                <code>
                  {WINDOWS_COMMAND}
                </code>

                <Button
                  type="button"
                  className="inventory-secondary-button"
                  onClick={
                    handleCopyCommand
                  }
                >
                  {commandCopied
                    ? "Copiée"
                    : "Copier"}
                </Button>
              </div>

              <p className="inventory-command-note">
                Le fichier inventory.json
                sera généré dans le dossier
                courant. L'identifiant de la
                machine est conservé entre
                les collectes.
              </p>
            </div>
          </>
        )}
      </Card>

      <Card>
        <div className="inventory-section-header">
          <div>
            <span className="inventory-section-eyebrow">
              Étape 2
            </span>

            <h2>
              Importer l'inventaire
            </h2>

            <p>
              Sélectionnez le fichier
              inventory.json généré par le
              collecteur Windows.
            </p>
          </div>
        </div>

        <label className="inventory-file-picker">
          <input
            type="file"
            accept=".json,application/json"
            onChange={(
              event,
            ) => {
              const file =
                event
                  .target
                  .files?.[0]
                ?? null;

              void handleFileChange(
                file,
              );
            }}
          />

          <span className="inventory-file-picker__icon">
            ↑
          </span>

          <strong>
            Sélectionner inventory.json
          </strong>

          <span>
            Fichier JSON inventory/v1
          </span>
        </label>

        {fileError && (
          <div className="inventory-inline-error">
            <strong>
              Fichier invalide
            </strong>

            <span>
              {fileError}
            </span>
          </div>
        )}

        {inventory
          && selectedFile && (
          <div className="inventory-file-summary">
            <div>
              <span>
                Fichier
              </span>

              <strong>
                {selectedFile.name}
              </strong>
            </div>

            <div>
              <span>
                Machine
              </span>

              <strong>
                {
                  inventory
                    .machine
                    .hostname
                }
              </strong>
            </div>

            <div>
              <span>
                Système
              </span>

              <strong>
                {
                  inventory
                    .machine
                    .os_name
                }
              </strong>
            </div>

            <div>
              <span>
                Composants
              </span>

              <strong>
                {
                  inventory
                    .components
                    .length
                }
              </strong>
            </div>

            <div>
              <span>
                Agent
              </span>

              <strong>
                {
                  inventory
                    .agent
                    .version
                }
              </strong>
            </div>

            <div>
              <span>
                Schéma
              </span>

              <strong>
                {
                  inventory
                    .schema_version
                }
              </strong>
            </div>
          </div>
        )}

        {inventory && (
          <div className="inventory-import-actions">
            <Button
              type="button"
              disabled={
                isImporting
              }
              onClick={() => {
                void handleImport();
              }}
            >
              {isImporting
                ? "Import en cours..."
                : "Importer l'inventaire"}
            </Button>
          </div>
        )}

        {isImporting && (
          <div className="loading-state inventory-import-loading">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Enregistrement de
              l'inventaire...
            </span>
          </div>
        )}

        {importError && (
          <div className="inventory-inline-error">
            <strong>
              Import impossible
            </strong>

            <span>
              {importError}
            </span>
          </div>
        )}

        {importResult && (
          <div className="inventory-success">
            <div className="inventory-success-header">
              <div className="inventory-success-icon">
                ✓
              </div>

              <div>
                <strong>
                  {
                    displayImportStatus(
                      importResult,
                    )
                  }
                </strong>

                <span>
                  L'inventaire a été traité
                  correctement par la
                  plateforme.
                </span>
              </div>
            </div>

            <div className="inventory-result-grid">
              <div>
                <span>
                  Composants
                </span>

                <strong>
                  {
                    importResult
                      .component_count
                  }
                </strong>
              </div>

              <div>
                <span>
                  Ajoutés
                </span>

                <strong>
                  {
                    importResult
                      .inserted_components
                  }
                </strong>
              </div>

              <div>
                <span>
                  Modifiés
                </span>

                <strong>
                  {
                    importResult
                      .updated_components
                  }
                </strong>
              </div>

              <div>
                <span>
                  Supprimés
                </span>

                <strong>
                  {
                    importResult
                      .deleted_components
                  }
                </strong>
              </div>
            </div>
          </div>
        )}
      </Card>
    </main>
  );
}