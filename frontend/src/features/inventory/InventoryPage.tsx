import {
  useEffect,
  useState,
} from "react";

import {
  Check,
  Copy,
  Database,
  FileText,
  Info,
  Monitor,
  Package,
  Terminal,
  Upload,
} from "lucide-react";

import type {
  LucideIcon,
} from "lucide-react";

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


type InventoryStepProps = {
  number: number;
  icon: LucideIcon;
  title: string;
  description: string;
};


function InventoryStep({
  number,
  icon: Icon,
  title,
  description,
}: InventoryStepProps) {
  return (
    <div className="inventory-flow-step">
      <span className="inventory-flow-step__icon">
        <Icon
          size={16}
          strokeWidth={1.8}
        />
      </span>

      <div className="inventory-flow-step__content">
        <span className="inventory-flow-step__number">
          Étape {number}
        </span>

        <strong>
          {title}
        </strong>

        <p>
          {description}
        </p>
      </div>
    </div>
  );
}


type InventoryFactProps = {
  icon: LucideIcon;
  label: string;
  value: string | number;
};


function InventoryFact({
  icon: Icon,
  label,
  value,
}: InventoryFactProps) {
  return (
    <div className="inventory-fact">
      <span className="inventory-fact__icon">
        <Icon
          size={15}
          strokeWidth={1.8}
        />
      </span>

      <div className="inventory-fact__content">
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

      <section
        className="inventory-flow"
        aria-label="Étapes d'import d'un inventaire"
      >
        <InventoryStep
          number={1}
          icon={FileText}
          title="Récupérer le script"
          description={
            "Enregistrer le collecteur "
            + "PowerShell sur la machine."
          }
        />

        <InventoryStep
          number={2}
          icon={Terminal}
          title="Lancer la collecte"
          description={
            "Exécuter le script pour "
            + "produire inventory.json."
          }
        />

        <InventoryStep
          number={3}
          icon={Upload}
          title="Importer le JSON"
          description={
            "Valider puis envoyer "
            + "l'inventaire à la plateforme."
          }
        />
      </section>

      <section className="inventory-workspace">
        <Card className="inventory-panel inventory-collector-panel">
          <div className="inventory-section-header">
            <div className="inventory-section-title">
              <span className="inventory-section-icon">
                <Terminal
                  size={16}
                  strokeWidth={1.8}
                />
              </span>

              <div>
                <span className="inventory-section-eyebrow">
                  Collecteur
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
            </div>

            <span className="inventory-platform-badge">
              <Monitor
                size={13}
                strokeWidth={1.8}
              />

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
                <div className="inventory-code-file">
                  <FileText
                    size={15}
                    strokeWidth={1.8}
                  />

                  <div>
                    <strong>
                      collect_inventory.ps1
                    </strong>

                    <span>
                      PowerShell
                    </span>
                  </div>
                </div>

                <Button
                  type="button"
                  className="inventory-code-button"
                  onClick={
                    handleCopyScript
                  }
                >
                  {scriptCopied ? (
                    <Check
                      size={14}
                      strokeWidth={2}
                    />
                  ) : (
                    <Copy
                      size={14}
                      strokeWidth={1.8}
                    />
                  )}

                  {scriptCopied
                    ? "Copié"
                    : "Copier"}
                </Button>
              </div>

              <pre className="inventory-code">
                <code>
                  {script}
                </code>
              </pre>

              <div className="inventory-command-section">
                <div className="inventory-command-heading">
                  <Terminal
                    size={15}
                    strokeWidth={1.8}
                  />

                  <div>
                    <strong>
                      Commande d'exécution
                    </strong>

                    <p>
                      Après avoir enregistré
                      collect_inventory.ps1,
                      exécutez cette commande
                      dans PowerShell.
                    </p>
                  </div>
                </div>

                <div className="inventory-command">
                  <code>
                    {WINDOWS_COMMAND}
                  </code>

                  <button
                    type="button"
                    className="inventory-copy-command"
                    onClick={
                      handleCopyCommand
                    }
                    aria-label="Copier la commande"
                  >
                    {commandCopied ? (
                      <Check
                        size={14}
                        strokeWidth={2}
                      />
                    ) : (
                      <Copy
                        size={14}
                        strokeWidth={1.8}
                      />
                    )}

                    <span>
                      {commandCopied
                        ? "Copiée"
                        : "Copier"}
                    </span>
                  </button>
                </div>

                <div className="inventory-note">
                  <Info
                    size={14}
                    strokeWidth={1.8}
                  />

                  <p>
                    Le fichier inventory.json
                    sera généré dans le dossier
                    courant. L'identifiant de la
                    machine est conservé entre
                    les collectes.
                  </p>
                </div>
              </div>
            </>
          )}
        </Card>

        <Card className="inventory-panel inventory-import-panel">
          <div className="inventory-section-header">
            <div className="inventory-section-title">
              <span className="inventory-section-icon">
                <Upload
                  size={16}
                  strokeWidth={1.8}
                />
              </span>

              <div>
                <span className="inventory-section-eyebrow">
                  Import
                </span>

                <h2>
                  Importer l'inventaire
                </h2>

                <p>
                  Sélectionnez le fichier
                  inventory.json généré par
                  le collecteur Windows.
                </p>
              </div>
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
              <Upload
                size={18}
                strokeWidth={1.7}
              />
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
            <section className="inventory-file-details">
              <InventoryFact
                icon={FileText}
                label="Fichier"
                value={
                  selectedFile.name
                }
              />

              <InventoryFact
                icon={Monitor}
                label="Machine"
                value={
                  inventory
                    .machine
                    .hostname
                }
              />

              <InventoryFact
                icon={Database}
                label="Système"
                value={
                  inventory
                    .machine
                    .os_name
                }
              />

              <InventoryFact
                icon={Package}
                label="Composants"
                value={
                  inventory
                    .components
                    .length
                }
              />

              <InventoryFact
                icon={Terminal}
                label="Agent"
                value={
                  inventory
                    .agent
                    .version
                }
              />

              <InventoryFact
                icon={FileText}
                label="Schéma"
                value={
                  inventory
                    .schema_version
                }
              />
            </section>
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
                <Upload
                  size={14}
                  strokeWidth={1.8}
                />

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
            <section className="inventory-success">
              <div className="inventory-success-header">
                <span className="inventory-success-icon">
                  <Check
                    size={16}
                    strokeWidth={2}
                  />
                </span>

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

              <div className="inventory-result-stats">
                <InventoryFact
                  icon={Package}
                  label="Composants"
                  value={
                    importResult
                      .component_count
                  }
                />

                <InventoryFact
                  icon={Database}
                  label="Ajoutés"
                  value={
                    importResult
                      .inserted_components
                  }
                />

                <InventoryFact
                  icon={FileText}
                  label="Modifiés"
                  value={
                    importResult
                      .updated_components
                  }
                />

                <InventoryFact
                  icon={Package}
                  label="Supprimés"
                  value={
                    importResult
                      .deleted_components
                  }
                />
              </div>
            </section>
          )}
        </Card>
      </section>
    </main>
  );
}