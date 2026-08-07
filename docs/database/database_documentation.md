# Documentation PostgreSQL

> Document généré automatiquement. Ne pas modifier manuellement.

## Informations générales

| Information | Valeur |
|---|---|
| Généré le | `2026-08-06T12:16:53.313045+00:00` |
| Base de données | `threat_intelligence` |
| Utilisateur de lecture | `threat_intel_reader` |
| Version PostgreSQL | `18.4` |
| Version Alembic | `817d8fdb14cd` |
| Comptages exacts | Oui |

## Vue métier canonique

> **Règle de comptage :** une vulnérabilité canonique est comptée une seule fois depuis `canonical.canonical_vulnerability`. Les identifiants, preuves et CWE ne sont pas ajoutés au total.

- Vulnérabilités canoniques : **1**
- Vulnérabilités avec CVE : **0**
- Vulnérabilités sans CVE : **1**
- Identifiant principal CVE : **0**
- Identifiant principal GHSA : **1**

### Enrichissement des CVE

- CVE avec au moins un CWE : **0**
- CVE sans CWE : **0**
- CVE avec preuve EPSS : **0**
- CVE sans preuve EPSS : **0**
- CVE avec au moins un enrichissement : **0**
- CVE sans aucun enrichissement : **0**

### Corrélation

- CVE multi-sources : **0**
- CVE mono-source : **0**

### Indicateurs web

- Indicateurs web canoniques : **0**
- Observations d'indicateurs web : **0**

Définition appliquée : Une CVE est considérée enrichie lorsqu'elle possède au moins une relation CWE canonique ou une preuve canonique provenant d'EPSS. Les CVE sans enrichissement restent incluses dans le total canonique.

### Répartition par statut

| Statut | Nombre |
|---|---:|
| provisional | 1 |

## Navigation

- [canonical](#schema-canonical)
  - [canonical.canonical_vulnerability](#canonical-canonical-vulnerability)
  - [canonical.canonical_vulnerability_evidence](#canonical-canonical-vulnerability-evidence)
  - [canonical.canonical_vulnerability_identifier](#canonical-canonical-vulnerability-identifier)
  - [canonical.canonical_vulnerability_weakness](#canonical-canonical-vulnerability-weakness)
  - [canonical.canonical_web_indicator](#canonical-canonical-web-indicator)
  - [canonical.canonical_web_indicator_observation](#canonical-canonical-web-indicator-observation)
- [normalized](#schema-normalized)
  - [normalized.cisa_kev_vulnerability](#normalized-cisa-kev-vulnerability)
  - [normalized.cwe_weakness](#normalized-cwe-weakness)
  - [normalized.epss_score](#normalized-epss-score)
  - [normalized.github_advisory_vulnerability](#normalized-github-advisory-vulnerability)
  - [normalized.phishtank_phishing](#normalized-phishtank-phishing)
  - [normalized.urlhaus_url](#normalized-urlhaus-url)
- [ops](#schema-ops)
  - [ops.ingestion_run](#ops-ingestion-run)
  - [ops.source](#ops-source)
  - [ops.sync_state](#ops-sync-state)
- [raw](#schema-raw)
  - [raw.ingestion_run_payload](#raw-ingestion-run-payload)
  - [raw.source_payload](#raw-source-payload)
- [threat_intel](#schema-threat-intel)
  - [threat_intel.alembic_version](#threat-intel-alembic-version)

## Résumé des schémas

| Schéma | Owner | Tables | Lignes exactes |
|---|---|---:|---:|
| `canonical` | `threat_intel_owner` | 6 | 3 |
| `normalized` | `threat_intel_owner` | 6 | 70700 |
| `ops` | `threat_intel_owner` | 3 | 32 |
| `raw` | `threat_intel_owner` | 2 | 138451 |
| `threat_intel` | `threat_intel_owner` | 1 | 1 |

## Schéma `canonical` {#schema-canonical}

- Owner : `threat_intel_owner`
- Nombre de tables : **6**

### `canonical.canonical_vulnerability`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 1 |
| Estimation PostgreSQL | 1 |
| Taille totale | 88.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 48.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `status` | `VARCHAR(20)` | Non | `'provisional'::character varying` | `False` | — |
| `correlation_version` | `INTEGER` | Non | `1` | `False` | — |
| `merged_into_id` | `UUID` | Oui | — | `False` | — |
| `created_at` | `TIMESTAMP` | Non | — | `False` | — |
| `updated_at` | `TIMESTAMP` | Non | — | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_canonical_vulnerability_correlation_version_positive` | CHECK | `CHECK (correlation_version > 0)` |
| `ck_canonical_vulnerability_merge_target_consistent` | CHECK | `CHECK (status::text = 'merged'::text AND merged_into_id IS NOT NULL OR status::text <> 'merged'::text AND merged_into_id IS NULL)` |
| `ck_canonical_vulnerability_merge_target_not_self` | CHECK | `CHECK (merged_into_id IS NULL OR merged_into_id <> id)` |
| `ck_canonical_vulnerability_status_valid` | CHECK | `CHECK (status::text = ANY (ARRAY['provisional'::character varying, 'active'::character varying, 'withdrawn'::character varying, 'rejected'::character varying, 'merged'::character varying]::text[]))` |
| `ck_canonical_vulnerability_timestamps_order` | CHECK | `CHECK (updated_at >= created_at)` |
| `fk_canonical_vulnerability_merged_into_id_canonical_vul_9d26` | FOREIGN KEY | `FOREIGN KEY (merged_into_id) REFERENCES canonical.canonical_vulnerability(id) ON DELETE RESTRICT` |
| `canonical_vulnerability_correlation_version_not_null` | n | `NOT NULL correlation_version` |
| `canonical_vulnerability_created_at_not_null` | n | `NOT NULL created_at` |
| `canonical_vulnerability_id_not_null` | n | `NOT NULL id` |
| `canonical_vulnerability_status_not_null` | n | `NOT NULL status` |
| `canonical_vulnerability_updated_at_not_null` | n | `NOT NULL updated_at` |
| `pk_canonical_vulnerability` | PRIMARY KEY | `PRIMARY KEY (id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `ix_canonical_vulnerability_merged_into_id` | Non | Non | Oui | `CREATE INDEX ix_canonical_vulnerability_merged_into_id ON canonical.canonical_vulnerability USING btree (merged_into_id)` |
| `ix_canonical_vulnerability_updated_at` | Non | Non | Oui | `CREATE INDEX ix_canonical_vulnerability_updated_at ON canonical.canonical_vulnerability USING btree (updated_at)` |
| `pk_canonical_vulnerability` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_canonical_vulnerability ON canonical.canonical_vulnerability USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `canonical.canonical_vulnerability_evidence`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 1 |
| Estimation PostgreSQL | 1 |
| Taille totale | 112.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 64.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `vulnerability_id` | `UUID` | Non | — | `False` | — |
| `source` | `VARCHAR(50)` | Non | — | `False` | — |
| `source_record_key` | `VARCHAR(255)` | Non | — | `False` | — |
| `normalized_record_id` | `VARCHAR(255)` | Non | — | `False` | — |
| `evidence_type` | `VARCHAR(64)` | Non | — | `False` | — |
| `correlation_rule` | `VARCHAR(64)` | Non | — | `False` | — |
| `observed_at` | `TIMESTAMP` | Non | — | `False` | — |
| `last_observed_at` | `TIMESTAMP` | Non | — | `False` | — |
| `source_published_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `source_modified_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `correlation_confidence` | `DOUBLE PRECISION` | Non | `1` | `False` | — |
| `record_hash` | `VARCHAR(64)` | Oui | — | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_canonical_vulnerability_evidence_correlation_confide_2e8c` | CHECK | `CHECK (correlation_confidence >= 0::double precision AND correlation_confidence <= 1::double precision)` |
| `ck_canonical_vulnerability_evidence_correlation_rule_fo_e9a3` | CHECK | `CHECK (correlation_rule::text ~ '^[a-z][a-z0-9_]*$'::text)` |
| `ck_canonical_vulnerability_evidence_normalized_record_i_3102` | CHECK | `CHECK (btrim(normalized_record_id::text) <> ''::text)` |
| `ck_canonical_vulnerability_evidence_observation_dates_order` | CHECK | `CHECK (last_observed_at >= observed_at)` |
| `ck_canonical_vulnerability_evidence_record_hash_format_valid` | CHECK | `CHECK (record_hash IS NULL OR record_hash::text ~ '^[a-f0-9]{64}$'::text)` |
| `ck_canonical_vulnerability_evidence_source_format_valid` | CHECK | `CHECK (source::text ~ '^[a-z][a-z0-9_]*$'::text)` |
| `ck_canonical_vulnerability_evidence_source_record_key_not_empty` | CHECK | `CHECK (btrim(source_record_key::text) <> ''::text)` |
| `ck_canonical_vulnerability_evidence_type_format_valid` | CHECK | `CHECK (evidence_type::text ~ '^[a-z][a-z0-9_]*$'::text)` |
| `fk_canonical_vulnerability_evidence_vulnerability_id_ca_545e` | FOREIGN KEY | `FOREIGN KEY (vulnerability_id) REFERENCES canonical.canonical_vulnerability(id) ON DELETE CASCADE` |
| `canonical_vulnerability_evidenc_correlation_confidence_not_null` | n | `NOT NULL correlation_confidence` |
| `canonical_vulnerability_evidence_correlation_rule_not_null` | n | `NOT NULL correlation_rule` |
| `canonical_vulnerability_evidence_evidence_type_not_null` | n | `NOT NULL evidence_type` |
| `canonical_vulnerability_evidence_id_not_null` | n | `NOT NULL id` |
| `canonical_vulnerability_evidence_last_observed_at_not_null` | n | `NOT NULL last_observed_at` |
| `canonical_vulnerability_evidence_normalized_record_id_not_null` | n | `NOT NULL normalized_record_id` |
| `canonical_vulnerability_evidence_observed_at_not_null` | n | `NOT NULL observed_at` |
| `canonical_vulnerability_evidence_source_not_null` | n | `NOT NULL source` |
| `canonical_vulnerability_evidence_source_record_key_not_null` | n | `NOT NULL source_record_key` |
| `canonical_vulnerability_evidence_vulnerability_id_not_null` | n | `NOT NULL vulnerability_id` |
| `pk_canonical_vulnerability_evidence` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `canonical_evidence_source_record` | UNIQUE | `UNIQUE (source, source_record_key)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `canonical_evidence_source_record` | Oui | Non | Oui | `CREATE UNIQUE INDEX canonical_evidence_source_record ON canonical.canonical_vulnerability_evidence USING btree (source, source_record_key)` |
| `ix_canonical_evidence_last_observed_at` | Non | Non | Oui | `CREATE INDEX ix_canonical_evidence_last_observed_at ON canonical.canonical_vulnerability_evidence USING btree (last_observed_at)` |
| `ix_canonical_evidence_vulnerability_id` | Non | Non | Oui | `CREATE INDEX ix_canonical_evidence_vulnerability_id ON canonical.canonical_vulnerability_evidence USING btree (vulnerability_id)` |
| `pk_canonical_vulnerability_evidence` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_canonical_vulnerability_evidence ON canonical.canonical_vulnerability_evidence USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `canonical.canonical_vulnerability_identifier`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 1 |
| Estimation PostgreSQL | 1 |
| Taille totale | 104.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 64.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `vulnerability_id` | `UUID` | Non | — | `False` | — |
| `namespace` | `VARCHAR(16)` | Non | — | `False` | — |
| `value` | `VARCHAR(64)` | Non | — | `False` | — |
| `is_primary` | `BOOLEAN` | Non | `false` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_canonical_vulnerability_identifier_namespace_valid` | CHECK | `CHECK (namespace::text = ANY (ARRAY['CVE'::character varying, 'GHSA'::character varying]::text[]))` |
| `ck_canonical_vulnerability_identifier_value_format_valid` | CHECK | `CHECK (namespace::text = 'CVE'::text AND value::text ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'::text OR namespace::text = 'GHSA'::text AND value::text ~ '^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$'::text)` |
| `fk_canonical_vulnerability_identifier_vulnerability_id__ac26` | FOREIGN KEY | `FOREIGN KEY (vulnerability_id) REFERENCES canonical.canonical_vulnerability(id) ON DELETE CASCADE` |
| `canonical_vulnerability_identifier_id_not_null` | n | `NOT NULL id` |
| `canonical_vulnerability_identifier_is_primary_not_null` | n | `NOT NULL is_primary` |
| `canonical_vulnerability_identifier_namespace_not_null` | n | `NOT NULL namespace` |
| `canonical_vulnerability_identifier_value_not_null` | n | `NOT NULL value` |
| `canonical_vulnerability_identifier_vulnerability_id_not_null` | n | `NOT NULL vulnerability_id` |
| `pk_canonical_vulnerability_identifier` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `canonical_identifier_namespace_value` | UNIQUE | `UNIQUE (namespace, value)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `canonical_identifier_namespace_value` | Oui | Non | Oui | `CREATE UNIQUE INDEX canonical_identifier_namespace_value ON canonical.canonical_vulnerability_identifier USING btree (namespace, value)` |
| `ix_canonical_identifier_vulnerability_id` | Non | Non | Oui | `CREATE INDEX ix_canonical_identifier_vulnerability_id ON canonical.canonical_vulnerability_identifier USING btree (vulnerability_id)` |
| `pk_canonical_vulnerability_identifier` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_canonical_vulnerability_identifier ON canonical.canonical_vulnerability_identifier USING btree (id)` |
| `uq_canonical_vulnerability_primary_identifier` | Oui | Non | Oui | `CREATE UNIQUE INDEX uq_canonical_vulnerability_primary_identifier ON canonical.canonical_vulnerability_identifier USING btree (vulnerability_id) WHERE (is_primary IS TRUE)` |

#### Triggers

Aucun trigger utilisateur.

### `canonical.canonical_vulnerability_weakness`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 0 |
| Estimation PostgreSQL | -1 |
| Taille totale | 96.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 80.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `vulnerability_id` | `UUID` | Non | — | `False` | — |
| `cwe_id` | `VARCHAR(32)` | Non | — | `False` | — |
| `source` | `VARCHAR(50)` | Non | — | `False` | — |
| `source_record_key` | `VARCHAR(255)` | Non | — | `False` | — |
| `normalized_record_id` | `VARCHAR(255)` | Non | — | `False` | — |
| `observed_at` | `TIMESTAMP` | Non | — | `False` | — |
| `last_observed_at` | `TIMESTAMP` | Non | — | `False` | — |
| `source_modified_at` | `TIMESTAMP` | Oui | — | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_canonical_vulnerability_weakness_cwe_id_valid` | CHECK | `CHECK (cwe_id::text ~ '^CWE-[1-9][0-9]*$'::text)` |
| `ck_canonical_vulnerability_weakness_normalized_record_i_ead0` | CHECK | `CHECK (btrim(normalized_record_id::text) <> ''::text)` |
| `ck_canonical_vulnerability_weakness_observation_dates_order` | CHECK | `CHECK (last_observed_at >= observed_at)` |
| `ck_canonical_vulnerability_weakness_source_format_valid` | CHECK | `CHECK (source::text ~ '^[a-z][a-z0-9_]*$'::text)` |
| `ck_canonical_vulnerability_weakness_source_record_key_not_empty` | CHECK | `CHECK (btrim(source_record_key::text) <> ''::text)` |
| `fk_canonical_vulnerability_weakness_cwe_id_cwe_weakness` | FOREIGN KEY | `FOREIGN KEY (cwe_id) REFERENCES normalized.cwe_weakness(cwe_id) ON DELETE RESTRICT` |
| `fk_canonical_vulnerability_weakness_vulnerability_id_ca_a670` | FOREIGN KEY | `FOREIGN KEY (vulnerability_id) REFERENCES canonical.canonical_vulnerability(id) ON DELETE CASCADE` |
| `canonical_vulnerability_weakness_cwe_id_not_null` | n | `NOT NULL cwe_id` |
| `canonical_vulnerability_weakness_id_not_null` | n | `NOT NULL id` |
| `canonical_vulnerability_weakness_last_observed_at_not_null` | n | `NOT NULL last_observed_at` |
| `canonical_vulnerability_weakness_normalized_record_id_not_null` | n | `NOT NULL normalized_record_id` |
| `canonical_vulnerability_weakness_observed_at_not_null` | n | `NOT NULL observed_at` |
| `canonical_vulnerability_weakness_source_not_null` | n | `NOT NULL source` |
| `canonical_vulnerability_weakness_source_record_key_not_null` | n | `NOT NULL source_record_key` |
| `canonical_vulnerability_weakness_vulnerability_id_not_null` | n | `NOT NULL vulnerability_id` |
| `pk_canonical_vulnerability_weakness` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `canonical_weakness_source_record_cwe` | UNIQUE | `UNIQUE (source, source_record_key, cwe_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `canonical_weakness_source_record_cwe` | Oui | Non | Oui | `CREATE UNIQUE INDEX canonical_weakness_source_record_cwe ON canonical.canonical_vulnerability_weakness USING btree (source, source_record_key, cwe_id)` |
| `ix_canonical_weakness_cwe_id` | Non | Non | Oui | `CREATE INDEX ix_canonical_weakness_cwe_id ON canonical.canonical_vulnerability_weakness USING btree (cwe_id)` |
| `ix_canonical_weakness_last_observed_at` | Non | Non | Oui | `CREATE INDEX ix_canonical_weakness_last_observed_at ON canonical.canonical_vulnerability_weakness USING btree (last_observed_at)` |
| `ix_canonical_weakness_vulnerability_id` | Non | Non | Oui | `CREATE INDEX ix_canonical_weakness_vulnerability_id ON canonical.canonical_vulnerability_weakness USING btree (vulnerability_id)` |
| `pk_canonical_vulnerability_weakness` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_canonical_vulnerability_weakness ON canonical.canonical_vulnerability_weakness USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `canonical.canonical_web_indicator`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 0 |
| Estimation PostgreSQL | -1 |
| Taille totale | 80.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 64.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `indicator_type` | `VARCHAR(16)` | Non | `'url'::character varying` | `False` | — |
| `canonical_value` | `TEXT` | Non | — | `False` | — |
| `value_hash` | `VARCHAR(64)` | Non | — | `False` | — |
| `hostname` | `VARCHAR(253)` | Non | — | `False` | — |
| `canonicalization_version` | `INTEGER` | Non | `1` | `False` | — |
| `created_at` | `TIMESTAMP` | Non | — | `False` | — |
| `updated_at` | `TIMESTAMP` | Non | — | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_canonical_web_indicator_canonical_value_length_valid` | CHECK | `CHECK (char_length(canonical_value) >= 1 AND char_length(canonical_value) <= 4096)` |
| `ck_canonical_web_indicator_canonicalization_version_positive` | CHECK | `CHECK (canonicalization_version > 0)` |
| `ck_canonical_web_indicator_hostname_length_valid` | CHECK | `CHECK (char_length(hostname::text) >= 1 AND char_length(hostname::text) <= 253)` |
| `ck_canonical_web_indicator_indicator_type_url` | CHECK | `CHECK (indicator_type::text = 'url'::text)` |
| `ck_canonical_web_indicator_timestamps_order` | CHECK | `CHECK (updated_at >= created_at)` |
| `ck_canonical_web_indicator_value_hash_sha256` | CHECK | `CHECK (value_hash::text ~ '^[a-f0-9]{64}$'::text)` |
| `canonical_web_indicator_canonical_value_not_null` | n | `NOT NULL canonical_value` |
| `canonical_web_indicator_canonicalization_version_not_null` | n | `NOT NULL canonicalization_version` |
| `canonical_web_indicator_created_at_not_null` | n | `NOT NULL created_at` |
| `canonical_web_indicator_hostname_not_null` | n | `NOT NULL hostname` |
| `canonical_web_indicator_id_not_null` | n | `NOT NULL id` |
| `canonical_web_indicator_indicator_type_not_null` | n | `NOT NULL indicator_type` |
| `canonical_web_indicator_updated_at_not_null` | n | `NOT NULL updated_at` |
| `canonical_web_indicator_value_hash_not_null` | n | `NOT NULL value_hash` |
| `pk_canonical_web_indicator` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `canonical_web_indicator_version_value_hash` | UNIQUE | `UNIQUE (canonicalization_version, value_hash)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `canonical_web_indicator_version_value_hash` | Oui | Non | Oui | `CREATE UNIQUE INDEX canonical_web_indicator_version_value_hash ON canonical.canonical_web_indicator USING btree (canonicalization_version, value_hash)` |
| `ix_canonical_web_indicator_hostname` | Non | Non | Oui | `CREATE INDEX ix_canonical_web_indicator_hostname ON canonical.canonical_web_indicator USING btree (hostname)` |
| `ix_canonical_web_indicator_updated_at` | Non | Non | Oui | `CREATE INDEX ix_canonical_web_indicator_updated_at ON canonical.canonical_web_indicator USING btree (updated_at)` |
| `pk_canonical_web_indicator` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_canonical_web_indicator ON canonical.canonical_web_indicator USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `canonical.canonical_web_indicator_observation`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 0 |
| Estimation PostgreSQL | -1 |
| Taille totale | 96.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 80.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `indicator_id` | `UUID` | Non | — | `False` | — |
| `source` | `VARCHAR(50)` | Non | — | `False` | — |
| `source_record_key` | `VARCHAR(255)` | Non | — | `False` | — |
| `normalized_record_id` | `UUID` | Non | — | `False` | — |
| `observed_at` | `TIMESTAMP` | Non | — | `False` | — |
| `last_observed_at` | `TIMESTAMP` | Non | — | `False` | — |
| `normalizer_version` | `VARCHAR(30)` | Non | — | `False` | — |
| `source_status` | `VARCHAR(64)` | Oui | — | `False` | — |
| `is_active` | `BOOLEAN` | Oui | — | `False` | — |
| `labels` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_canonical_web_indicator_observation_labels_array_bounded` | CHECK | `CHECK (jsonb_typeof(labels) = 'array'::text AND jsonb_array_length(labels) <= 20)` |
| `ck_canonical_web_indicator_observation_normalizer_versi_f15c` | CHECK | `CHECK (char_length(normalizer_version::text) >= 1 AND char_length(normalizer_version::text) <= 30)` |
| `ck_canonical_web_indicator_observation_observation_dates_order` | CHECK | `CHECK (last_observed_at >= observed_at)` |
| `ck_canonical_web_indicator_observation_source_format_valid` | CHECK | `CHECK (source::text ~ '^[a-z][a-z0-9_]*$'::text)` |
| `ck_canonical_web_indicator_observation_source_record_ke_2897` | CHECK | `CHECK (btrim(source_record_key::text) <> ''::text)` |
| `ck_canonical_web_indicator_observation_source_status_fo_2d0f` | CHECK | `CHECK (source_status IS NULL OR source_status::text ~ '^[a-z][a-z0-9_]*$'::text)` |
| `fk_canonical_web_indicator_observation_indicator_id_can_ae46` | FOREIGN KEY | `FOREIGN KEY (indicator_id) REFERENCES canonical.canonical_web_indicator(id) ON DELETE CASCADE` |
| `canonical_web_indicator_observati_normalized_record_id_not_null` | n | `NOT NULL normalized_record_id` |
| `canonical_web_indicator_observation_id_not_null` | n | `NOT NULL id` |
| `canonical_web_indicator_observation_indicator_id_not_null` | n | `NOT NULL indicator_id` |
| `canonical_web_indicator_observation_labels_not_null` | n | `NOT NULL labels` |
| `canonical_web_indicator_observation_last_observed_at_not_null` | n | `NOT NULL last_observed_at` |
| `canonical_web_indicator_observation_normalizer_version_not_null` | n | `NOT NULL normalizer_version` |
| `canonical_web_indicator_observation_observed_at_not_null` | n | `NOT NULL observed_at` |
| `canonical_web_indicator_observation_source_not_null` | n | `NOT NULL source` |
| `canonical_web_indicator_observation_source_record_key_not_null` | n | `NOT NULL source_record_key` |
| `pk_canonical_web_indicator_observation` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `canonical_web_observation_source_record` | UNIQUE | `UNIQUE (source, source_record_key)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `canonical_web_observation_source_record` | Oui | Non | Oui | `CREATE UNIQUE INDEX canonical_web_observation_source_record ON canonical.canonical_web_indicator_observation USING btree (source, source_record_key)` |
| `ix_canonical_web_observation_indicator_id` | Non | Non | Oui | `CREATE INDEX ix_canonical_web_observation_indicator_id ON canonical.canonical_web_indicator_observation USING btree (indicator_id)` |
| `ix_canonical_web_observation_last_observed_at` | Non | Non | Oui | `CREATE INDEX ix_canonical_web_observation_last_observed_at ON canonical.canonical_web_indicator_observation USING btree (last_observed_at)` |
| `ix_canonical_web_observation_normalized_record_id` | Non | Non | Oui | `CREATE INDEX ix_canonical_web_observation_normalized_record_id ON canonical.canonical_web_indicator_observation USING btree (normalized_record_id)` |
| `pk_canonical_web_indicator_observation` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_canonical_web_indicator_observation ON canonical.canonical_web_indicator_observation USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

## Schéma `normalized` {#schema-normalized}

- Owner : `threat_intel_owner`
- Nombre de tables : **6**

### `normalized.cisa_kev_vulnerability`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 1655 |
| Estimation PostgreSQL | 1655 |
| Taille totale | 1.42 MiB |
| Taille des données | 1.06 MiB |
| Taille des index | 328.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `raw_payload_id` | `UUID` | Non | — | `False` | — |
| `cve_id` | `VARCHAR(32)` | Non | — | `False` | — |
| `vendor_project` | `VARCHAR(255)` | Non | — | `False` | — |
| `product` | `VARCHAR(255)` | Non | — | `False` | — |
| `vulnerability_name` | `TEXT` | Non | — | `False` | — |
| `date_added` | `DATE` | Non | — | `False` | — |
| `short_description` | `TEXT` | Non | — | `False` | — |
| `required_action` | `TEXT` | Non | — | `False` | — |
| `due_date` | `DATE` | Non | — | `False` | — |
| `known_ransomware_campaign_use` | `VARCHAR(20)` | Non | — | `False` | — |
| `notes` | `TEXT` | Oui | — | `False` | — |
| `cwes` | `ARRAY` | Non | `'{}'::character varying[]` | `False` | — |
| `normalizer_version` | `VARCHAR(30)` | Non | — | `False` | — |
| `normalized_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_cisa_kev_vulnerability_ransomware_campaign_use_valid` | CHECK | `CHECK (known_ransomware_campaign_use::text = ANY (ARRAY['known'::character varying, 'unknown'::character varying]::text[]))` |
| `fk_cisa_kev_vulnerability_raw_payload_id_source_payload` | FOREIGN KEY | `FOREIGN KEY (raw_payload_id) REFERENCES raw.source_payload(id) ON DELETE RESTRICT` |
| `cisa_kev_vulnerability_cve_id_not_null` | n | `NOT NULL cve_id` |
| `cisa_kev_vulnerability_cwes_not_null` | n | `NOT NULL cwes` |
| `cisa_kev_vulnerability_date_added_not_null` | n | `NOT NULL date_added` |
| `cisa_kev_vulnerability_due_date_not_null` | n | `NOT NULL due_date` |
| `cisa_kev_vulnerability_id_not_null` | n | `NOT NULL id` |
| `cisa_kev_vulnerability_known_ransomware_campaign_use_not_null` | n | `NOT NULL known_ransomware_campaign_use` |
| `cisa_kev_vulnerability_normalized_at_not_null` | n | `NOT NULL normalized_at` |
| `cisa_kev_vulnerability_normalizer_version_not_null` | n | `NOT NULL normalizer_version` |
| `cisa_kev_vulnerability_product_not_null` | n | `NOT NULL product` |
| `cisa_kev_vulnerability_raw_payload_id_not_null` | n | `NOT NULL raw_payload_id` |
| `cisa_kev_vulnerability_required_action_not_null` | n | `NOT NULL required_action` |
| `cisa_kev_vulnerability_short_description_not_null` | n | `NOT NULL short_description` |
| `cisa_kev_vulnerability_vendor_project_not_null` | n | `NOT NULL vendor_project` |
| `cisa_kev_vulnerability_vulnerability_name_not_null` | n | `NOT NULL vulnerability_name` |
| `pk_cisa_kev_vulnerability` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `cisa_kev_raw_payload` | UNIQUE | `UNIQUE (raw_payload_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `cisa_kev_raw_payload` | Oui | Non | Oui | `CREATE UNIQUE INDEX cisa_kev_raw_payload ON normalized.cisa_kev_vulnerability USING btree (raw_payload_id)` |
| `ix_cisa_kev_vulnerability_cve_id_id` | Non | Non | Oui | `CREATE INDEX ix_cisa_kev_vulnerability_cve_id_id ON normalized.cisa_kev_vulnerability USING btree (cve_id, id)` |
| `ix_cisa_kev_vulnerability_due_date` | Non | Non | Oui | `CREATE INDEX ix_cisa_kev_vulnerability_due_date ON normalized.cisa_kev_vulnerability USING btree (due_date)` |
| `pk_cisa_kev_vulnerability` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_cisa_kev_vulnerability ON normalized.cisa_kev_vulnerability USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `normalized.cwe_weakness`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 209 |
| Estimation PostgreSQL | 209 |
| Taille totale | 952.00 KiB |
| Taille des données | 448.00 KiB |
| Taille des index | 16.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `cwe_id` | `VARCHAR(32)` | Non | — | `False` | — |
| `name` | `TEXT` | Non | — | `False` | — |
| `description` | `TEXT` | Non | — | `False` | — |
| `abstraction` | `VARCHAR(50)` | Oui | — | `False` | — |
| `structure` | `VARCHAR(50)` | Oui | — | `False` | — |
| `status` | `VARCHAR(50)` | Oui | — | `False` | — |
| `extended_description` | `TEXT` | Oui | — | `False` | — |
| `likelihood_of_exploit` | `VARCHAR(50)` | Oui | — | `False` | — |
| `mapping_usage` | `TEXT` | Oui | — | `False` | — |
| `mapping_rationale` | `TEXT` | Oui | — | `False` | — |
| `relationships` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `consequences` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `mitigations` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `detection_methods` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `applicable_platforms` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `modes_of_introduction` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `alternate_terms` | `ARRAY` | Non | `'{}'::text[]` | `False` | — |
| `related_capec_ids` | `ARRAY` | Non | `'{}'::character varying[]` | `False` | — |
| `catalog_version` | `VARCHAR(50)` | Oui | — | `False` | — |
| `catalog_date` | `VARCHAR(32)` | Oui | — | `False` | — |
| `synchronized_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_cwe_weakness_cwe_id_valid` | CHECK | `CHECK (cwe_id::text ~ '^CWE-[1-9][0-9]*$'::text)` |
| `cwe_weakness_alternate_terms_not_null` | n | `NOT NULL alternate_terms` |
| `cwe_weakness_applicable_platforms_not_null` | n | `NOT NULL applicable_platforms` |
| `cwe_weakness_consequences_not_null` | n | `NOT NULL consequences` |
| `cwe_weakness_cwe_id_not_null` | n | `NOT NULL cwe_id` |
| `cwe_weakness_description_not_null` | n | `NOT NULL description` |
| `cwe_weakness_detection_methods_not_null` | n | `NOT NULL detection_methods` |
| `cwe_weakness_mitigations_not_null` | n | `NOT NULL mitigations` |
| `cwe_weakness_modes_of_introduction_not_null` | n | `NOT NULL modes_of_introduction` |
| `cwe_weakness_name_not_null` | n | `NOT NULL name` |
| `cwe_weakness_related_capec_ids_not_null` | n | `NOT NULL related_capec_ids` |
| `cwe_weakness_relationships_not_null` | n | `NOT NULL relationships` |
| `cwe_weakness_synchronized_at_not_null` | n | `NOT NULL synchronized_at` |
| `pk_cwe_weakness` | PRIMARY KEY | `PRIMARY KEY (cwe_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `pk_cwe_weakness` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_cwe_weakness ON normalized.cwe_weakness USING btree (cwe_id)` |

#### Triggers

Aucun trigger utilisateur.

### `normalized.epss_score`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 2 |
| Estimation PostgreSQL | 2 |
| Taille totale | 56.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 16.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `cve_id` | `VARCHAR(32)` | Non | — | `False` | — |
| `epss_score` | `DOUBLE PRECISION` | Non | — | `False` | — |
| `percentile` | `DOUBLE PRECISION` | Non | — | `False` | — |
| `score_date` | `DATE` | Non | — | `False` | — |
| `api_version` | `VARCHAR(20)` | Oui | — | `False` | — |
| `synchronized_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_epss_score_cve_id_valid` | CHECK | `CHECK (cve_id::text ~ '^CVE-[0-9]{4}-[0-9]{4,}$'::text)` |
| `ck_epss_score_epss_score_range` | CHECK | `CHECK (epss_score >= 0::double precision AND epss_score <= 1::double precision)` |
| `ck_epss_score_percentile_range` | CHECK | `CHECK (percentile >= 0::double precision AND percentile <= 1::double precision)` |
| `epss_score_cve_id_not_null` | n | `NOT NULL cve_id` |
| `epss_score_epss_score_not_null` | n | `NOT NULL epss_score` |
| `epss_score_percentile_not_null` | n | `NOT NULL percentile` |
| `epss_score_score_date_not_null` | n | `NOT NULL score_date` |
| `epss_score_synchronized_at_not_null` | n | `NOT NULL synchronized_at` |
| `pk_epss_score` | PRIMARY KEY | `PRIMARY KEY (cve_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `pk_epss_score` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_epss_score ON normalized.epss_score USING btree (cve_id)` |

#### Triggers

Aucun trigger utilisateur.

### `normalized.github_advisory_vulnerability`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 1300 |
| Estimation PostgreSQL | 1300 |
| Taille totale | 2.32 MiB |
| Taille des données | 1.73 MiB |
| Taille des index | 400.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `raw_payload_id` | `UUID` | Non | — | `False` | — |
| `ghsa_id` | `VARCHAR(32)` | Non | — | `False` | — |
| `cve_id` | `VARCHAR(32)` | Oui | — | `False` | — |
| `advisory_type` | `VARCHAR(50)` | Oui | — | `False` | — |
| `severity` | `VARCHAR(20)` | Oui | — | `False` | — |
| `summary` | `TEXT` | Oui | — | `False` | — |
| `description` | `TEXT` | Oui | — | `False` | — |
| `published_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `updated_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `reviewed_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `withdrawn_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `cvss_score` | `DOUBLE PRECISION` | Oui | — | `False` | — |
| `cvss_metrics` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `epss_score` | `DOUBLE PRECISION` | Oui | — | `False` | — |
| `epss_percentile` | `DOUBLE PRECISION` | Oui | — | `False` | — |
| `affected_packages` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `cwe_ids` | `ARRAY` | Non | `'{}'::character varying[]` | `False` | — |
| `references` | `ARRAY` | Non | `'{}'::text[]` | `False` | — |
| `api_url` | `TEXT` | Oui | — | `False` | — |
| `html_url` | `TEXT` | Oui | — | `False` | — |
| `repository_advisory_url` | `TEXT` | Oui | — | `False` | — |
| `source_code_locations` | `ARRAY` | Non | `'{}'::text[]` | `False` | — |
| `normalizer_version` | `VARCHAR(30)` | Non | — | `False` | — |
| `normalized_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_github_advisory_vulnerability_cvss_score_range` | CHECK | `CHECK (cvss_score IS NULL OR cvss_score >= 0::double precision AND cvss_score <= 10::double precision)` |
| `ck_github_advisory_vulnerability_epss_percentile_range` | CHECK | `CHECK (epss_percentile IS NULL OR epss_percentile >= 0::double precision AND epss_percentile <= 1::double precision)` |
| `ck_github_advisory_vulnerability_epss_score_range` | CHECK | `CHECK (epss_score IS NULL OR epss_score >= 0::double precision AND epss_score <= 1::double precision)` |
| `fk_github_advisory_vulnerability_raw_payload_id_source_payload` | FOREIGN KEY | `FOREIGN KEY (raw_payload_id) REFERENCES raw.source_payload(id) ON DELETE RESTRICT` |
| `github_advisory_vulnerability_affected_packages_not_null` | n | `NOT NULL affected_packages` |
| `github_advisory_vulnerability_cvss_metrics_not_null` | n | `NOT NULL cvss_metrics` |
| `github_advisory_vulnerability_cwe_ids_not_null` | n | `NOT NULL cwe_ids` |
| `github_advisory_vulnerability_ghsa_id_not_null` | n | `NOT NULL ghsa_id` |
| `github_advisory_vulnerability_id_not_null` | n | `NOT NULL id` |
| `github_advisory_vulnerability_normalized_at_not_null` | n | `NOT NULL normalized_at` |
| `github_advisory_vulnerability_normalizer_version_not_null` | n | `NOT NULL normalizer_version` |
| `github_advisory_vulnerability_raw_payload_id_not_null` | n | `NOT NULL raw_payload_id` |
| `github_advisory_vulnerability_references_not_null` | n | `NOT NULL "references"` |
| `github_advisory_vulnerability_source_code_locations_not_null` | n | `NOT NULL source_code_locations` |
| `pk_github_advisory_vulnerability` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `github_advisory_raw_payload` | UNIQUE | `UNIQUE (raw_payload_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `github_advisory_raw_payload` | Oui | Non | Oui | `CREATE UNIQUE INDEX github_advisory_raw_payload ON normalized.github_advisory_vulnerability USING btree (raw_payload_id)` |
| `ix_github_advisory_vulnerability_cve_id` | Non | Non | Oui | `CREATE INDEX ix_github_advisory_vulnerability_cve_id ON normalized.github_advisory_vulnerability USING btree (cve_id)` |
| `ix_github_advisory_vulnerability_ghsa_id_id` | Non | Non | Oui | `CREATE INDEX ix_github_advisory_vulnerability_ghsa_id_id ON normalized.github_advisory_vulnerability USING btree (ghsa_id, id)` |
| `ix_github_advisory_vulnerability_ghsa_updated` | Non | Non | Oui | `CREATE INDEX ix_github_advisory_vulnerability_ghsa_updated ON normalized.github_advisory_vulnerability USING btree (ghsa_id, updated_at)` |
| `pk_github_advisory_vulnerability` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_github_advisory_vulnerability ON normalized.github_advisory_vulnerability USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `normalized.phishtank_phishing`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 67524 |
| Estimation PostgreSQL | 63153 |
| Taille totale | 39.86 MiB |
| Taille des données | 29.08 MiB |
| Taille des index | 10.57 MiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `raw_payload_id` | `UUID` | Non | — | `False` | — |
| `phish_id` | `BIGINT` | Non | — | `False` | — |
| `phishing_url` | `TEXT` | Non | — | `False` | — |
| `hostname` | `VARCHAR(253)` | Non | — | `False` | — |
| `phish_detail_url` | `TEXT` | Oui | — | `False` | — |
| `submission_time` | `TIMESTAMP` | Oui | — | `False` | — |
| `verification_time` | `TIMESTAMP` | Oui | — | `False` | — |
| `verified` | `BOOLEAN` | Oui | — | `False` | — |
| `online` | `BOOLEAN` | Oui | — | `False` | — |
| `target` | `VARCHAR(255)` | Oui | — | `False` | — |
| `network_details` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `normalizer_version` | `VARCHAR(30)` | Non | — | `False` | — |
| `normalized_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_phishtank_phishing_hostname_length_valid` | CHECK | `CHECK (char_length(hostname::text) >= 1 AND char_length(hostname::text) <= 253)` |
| `ck_phishtank_phishing_network_details_array` | CHECK | `CHECK (jsonb_typeof(network_details) = 'array'::text)` |
| `ck_phishtank_phishing_phish_id_positive` | CHECK | `CHECK (phish_id > 0)` |
| `ck_phishtank_phishing_phishing_url_length_valid` | CHECK | `CHECK (char_length(phishing_url) >= 1 AND char_length(phishing_url) <= 4096)` |
| `ck_phishtank_phishing_verification_time_order` | CHECK | `CHECK (verification_time IS NULL OR submission_time IS NULL OR verification_time >= submission_time)` |
| `fk_phishtank_phishing_raw_payload_id_source_payload` | FOREIGN KEY | `FOREIGN KEY (raw_payload_id) REFERENCES raw.source_payload(id) ON DELETE RESTRICT` |
| `phishtank_phishing_hostname_not_null` | n | `NOT NULL hostname` |
| `phishtank_phishing_id_not_null` | n | `NOT NULL id` |
| `phishtank_phishing_network_details_not_null` | n | `NOT NULL network_details` |
| `phishtank_phishing_normalized_at_not_null` | n | `NOT NULL normalized_at` |
| `phishtank_phishing_normalizer_version_not_null` | n | `NOT NULL normalizer_version` |
| `phishtank_phishing_phish_id_not_null` | n | `NOT NULL phish_id` |
| `phishtank_phishing_phishing_url_not_null` | n | `NOT NULL phishing_url` |
| `phishtank_phishing_raw_payload_id_not_null` | n | `NOT NULL raw_payload_id` |
| `pk_phishtank_phishing` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `phishtank_phishing_raw_payload` | UNIQUE | `UNIQUE (raw_payload_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `ix_phishtank_phishing_hostname` | Non | Non | Oui | `CREATE INDEX ix_phishtank_phishing_hostname ON normalized.phishtank_phishing USING btree (hostname)` |
| `ix_phishtank_phishing_phish_id` | Non | Non | Oui | `CREATE INDEX ix_phishtank_phishing_phish_id ON normalized.phishtank_phishing USING btree (phish_id)` |
| `ix_phishtank_phishing_status` | Non | Non | Oui | `CREATE INDEX ix_phishtank_phishing_status ON normalized.phishtank_phishing USING btree (verified, online)` |
| `phishtank_phishing_raw_payload` | Oui | Non | Oui | `CREATE UNIQUE INDEX phishtank_phishing_raw_payload ON normalized.phishtank_phishing USING btree (raw_payload_id)` |
| `pk_phishtank_phishing` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_phishtank_phishing ON normalized.phishtank_phishing USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `normalized.urlhaus_url`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 10 |
| Estimation PostgreSQL | -1 |
| Taille totale | 112.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 96.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `raw_payload_id` | `UUID` | Non | — | `False` | — |
| `urlhaus_id` | `BIGINT` | Non | — | `False` | — |
| `malicious_url` | `TEXT` | Non | — | `False` | — |
| `hostname` | `VARCHAR(253)` | Non | — | `False` | — |
| `urlhaus_reference` | `TEXT` | Oui | — | `False` | — |
| `url_status` | `VARCHAR(32)` | Oui | — | `False` | — |
| `date_added` | `TIMESTAMP` | Oui | — | `False` | — |
| `threat_type` | `VARCHAR(100)` | Oui | — | `False` | — |
| `reporter` | `VARCHAR(255)` | Oui | — | `False` | — |
| `larted` | `BOOLEAN` | Oui | — | `False` | — |
| `tags` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `blacklists` | `JSONB` | Non | `'[]'::jsonb` | `False` | — |
| `normalizer_version` | `VARCHAR(30)` | Non | — | `False` | — |
| `normalized_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_urlhaus_url_blacklists_array_bounded` | CHECK | `CHECK (jsonb_typeof(blacklists) = 'array'::text AND jsonb_array_length(blacklists) <= 50)` |
| `ck_urlhaus_url_hostname_length_valid` | CHECK | `CHECK (char_length(hostname::text) >= 1 AND char_length(hostname::text) <= 253)` |
| `ck_urlhaus_url_malicious_url_length_valid` | CHECK | `CHECK (char_length(malicious_url) >= 1 AND char_length(malicious_url) <= 4096)` |
| `ck_urlhaus_url_normalizer_version_length_valid` | CHECK | `CHECK (char_length(normalizer_version::text) >= 1 AND char_length(normalizer_version::text) <= 30)` |
| `ck_urlhaus_url_tags_array_bounded` | CHECK | `CHECK (jsonb_typeof(tags) = 'array'::text AND jsonb_array_length(tags) <= 100)` |
| `ck_urlhaus_url_urlhaus_id_positive` | CHECK | `CHECK (urlhaus_id > 0)` |
| `ck_urlhaus_url_urlhaus_reference_length_valid` | CHECK | `CHECK (urlhaus_reference IS NULL OR char_length(urlhaus_reference) >= 1 AND char_length(urlhaus_reference) <= 4096)` |
| `fk_urlhaus_url_raw_payload_id_source_payload` | FOREIGN KEY | `FOREIGN KEY (raw_payload_id) REFERENCES raw.source_payload(id) ON DELETE RESTRICT` |
| `urlhaus_url_blacklists_not_null` | n | `NOT NULL blacklists` |
| `urlhaus_url_hostname_not_null` | n | `NOT NULL hostname` |
| `urlhaus_url_id_not_null` | n | `NOT NULL id` |
| `urlhaus_url_malicious_url_not_null` | n | `NOT NULL malicious_url` |
| `urlhaus_url_normalized_at_not_null` | n | `NOT NULL normalized_at` |
| `urlhaus_url_normalizer_version_not_null` | n | `NOT NULL normalizer_version` |
| `urlhaus_url_raw_payload_id_not_null` | n | `NOT NULL raw_payload_id` |
| `urlhaus_url_tags_not_null` | n | `NOT NULL tags` |
| `urlhaus_url_urlhaus_id_not_null` | n | `NOT NULL urlhaus_id` |
| `pk_urlhaus_url` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `urlhaus_url_raw_payload` | UNIQUE | `UNIQUE (raw_payload_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `ix_urlhaus_url_date_added` | Non | Non | Oui | `CREATE INDEX ix_urlhaus_url_date_added ON normalized.urlhaus_url USING btree (date_added)` |
| `ix_urlhaus_url_hostname` | Non | Non | Oui | `CREATE INDEX ix_urlhaus_url_hostname ON normalized.urlhaus_url USING btree (hostname)` |
| `ix_urlhaus_url_status` | Non | Non | Oui | `CREATE INDEX ix_urlhaus_url_status ON normalized.urlhaus_url USING btree (url_status)` |
| `ix_urlhaus_url_urlhaus_id` | Non | Non | Oui | `CREATE INDEX ix_urlhaus_url_urlhaus_id ON normalized.urlhaus_url USING btree (urlhaus_id)` |
| `pk_urlhaus_url` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_urlhaus_url ON normalized.urlhaus_url USING btree (id)` |
| `urlhaus_url_raw_payload` | Oui | Non | Oui | `CREATE UNIQUE INDEX urlhaus_url_raw_payload ON normalized.urlhaus_url USING btree (raw_payload_id)` |

#### Triggers

Aucun trigger utilisateur.

## Schéma `ops` {#schema-ops}

- Owner : `threat_intel_owner`
- Nombre de tables : **3**

### `ops.ingestion_run`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 22 |
| Estimation PostgreSQL | 22 |
| Taille totale | 88.00 KiB |
| Taille des données | 16.00 KiB |
| Taille des index | 32.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `source_id` | `UUID` | Non | — | `False` | — |
| `status` | `VARCHAR(30)` | Non | — | `False` | — |
| `started_at` | `TIMESTAMP` | Non | `now()` | `False` | — |
| `finished_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `records_received` | `INTEGER` | Non | `0` | `False` | — |
| `records_succeeded` | `INTEGER` | Non | `0` | `False` | — |
| `records_failed` | `INTEGER` | Non | `0` | `False` | — |
| `error_summary` | `TEXT` | Oui | — | `False` | — |
| `connector_version` | `VARCHAR(100)` | Oui | — | `False` | — |
| `metadata` | `JSONB` | Non | `'{}'::jsonb` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_ingestion_run_records_failed_non_negative` | CHECK | `CHECK (records_failed >= 0)` |
| `ck_ingestion_run_records_received_non_negative` | CHECK | `CHECK (records_received >= 0)` |
| `ck_ingestion_run_records_succeeded_non_negative` | CHECK | `CHECK (records_succeeded >= 0)` |
| `fk_ingestion_run_source_id_source` | FOREIGN KEY | `FOREIGN KEY (source_id) REFERENCES ops.source(id) ON DELETE RESTRICT` |
| `ingestion_run_id_not_null` | n | `NOT NULL id` |
| `ingestion_run_metadata_not_null` | n | `NOT NULL metadata` |
| `ingestion_run_records_failed_not_null` | n | `NOT NULL records_failed` |
| `ingestion_run_records_received_not_null` | n | `NOT NULL records_received` |
| `ingestion_run_records_succeeded_not_null` | n | `NOT NULL records_succeeded` |
| `ingestion_run_source_id_not_null` | n | `NOT NULL source_id` |
| `ingestion_run_started_at_not_null` | n | `NOT NULL started_at` |
| `ingestion_run_status_not_null` | n | `NOT NULL status` |
| `pk_ingestion_run` | PRIMARY KEY | `PRIMARY KEY (id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `ix_ingestion_run_source_id` | Non | Non | Oui | `CREATE INDEX ix_ingestion_run_source_id ON ops.ingestion_run USING btree (source_id)` |
| `pk_ingestion_run` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_ingestion_run ON ops.ingestion_run USING btree (id)` |

#### Triggers

Aucun trigger utilisateur.

### `ops.source`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 6 |
| Estimation PostgreSQL | 6 |
| Taille totale | 80.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 32.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `code` | `VARCHAR(50)` | Non | — | `False` | — |
| `name` | `VARCHAR(150)` | Non | — | `False` | — |
| `base_url` | `VARCHAR(500)` | Oui | — | `False` | — |
| `enabled` | `BOOLEAN` | Non | `true` | `False` | — |
| `created_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `source_code_not_null` | n | `NOT NULL code` |
| `source_created_at_not_null` | n | `NOT NULL created_at` |
| `source_enabled_not_null` | n | `NOT NULL enabled` |
| `source_id_not_null` | n | `NOT NULL id` |
| `source_name_not_null` | n | `NOT NULL name` |
| `pk_source` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `uq_source_code` | UNIQUE | `UNIQUE (code)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `pk_source` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_source ON ops.source USING btree (id)` |
| `uq_source_code` | Oui | Non | Oui | `CREATE UNIQUE INDEX uq_source_code ON ops.source USING btree (code)` |

#### Triggers

Aucun trigger utilisateur.

### `ops.sync_state`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 4 |
| Estimation PostgreSQL | 4 |
| Taille totale | 64.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 16.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `source_id` | `UUID` | Non | — | `False` | — |
| `cursor` | `TEXT` | Oui | — | `False` | — |
| `last_success_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `last_attempt_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `metadata` | `JSONB` | Non | `'{}'::jsonb` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `fk_sync_state_source_id_source` | FOREIGN KEY | `FOREIGN KEY (source_id) REFERENCES ops.source(id) ON DELETE CASCADE` |
| `sync_state_metadata_not_null` | n | `NOT NULL metadata` |
| `sync_state_source_id_not_null` | n | `NOT NULL source_id` |
| `pk_sync_state` | PRIMARY KEY | `PRIMARY KEY (source_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `pk_sync_state` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_sync_state ON ops.sync_state USING btree (source_id)` |

#### Triggers

Aucun trigger utilisateur.

## Schéma `raw` {#schema-raw}

- Owner : `threat_intel_owner`
- Nombre de tables : **2**

### `raw.ingestion_run_payload`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 67953 |
| Estimation PostgreSQL | 67833 |
| Taille totale | 11.04 MiB |
| Taille des données | 4.44 MiB |
| Taille des index | 6.57 MiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `ingestion_run_id` | `UUID` | Non | — | `False` | — |
| `raw_payload_id` | `UUID` | Non | — | `False` | — |
| `observed_at` | `TIMESTAMP` | Non | `now()` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `fk_ingestion_run_payload_ingestion_run_id_ingestion_run` | FOREIGN KEY | `FOREIGN KEY (ingestion_run_id) REFERENCES ops.ingestion_run(id) ON DELETE CASCADE` |
| `fk_ingestion_run_payload_raw_payload_id_source_payload` | FOREIGN KEY | `FOREIGN KEY (raw_payload_id) REFERENCES raw.source_payload(id) ON DELETE CASCADE` |
| `ingestion_run_payload_ingestion_run_id_not_null` | n | `NOT NULL ingestion_run_id` |
| `ingestion_run_payload_observed_at_not_null` | n | `NOT NULL observed_at` |
| `ingestion_run_payload_raw_payload_id_not_null` | n | `NOT NULL raw_payload_id` |
| `pk_ingestion_run_payload` | PRIMARY KEY | `PRIMARY KEY (ingestion_run_id, raw_payload_id)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `ix_ingestion_run_payload_raw_payload_id` | Non | Non | Oui | `CREATE INDEX ix_ingestion_run_payload_raw_payload_id ON raw.ingestion_run_payload USING btree (raw_payload_id)` |
| `pk_ingestion_run_payload` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_ingestion_run_payload ON raw.ingestion_run_payload USING btree (ingestion_run_id, raw_payload_id)` |

#### Triggers

Aucun trigger utilisateur.

### `raw.source_payload`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 70498 |
| Estimation PostgreSQL | 70488 |
| Taille totale | 88.37 MiB |
| Taille des données | 61.76 MiB |
| Taille des index | 25.66 MiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `id` | `UUID` | Non | — | `False` | — |
| `source_id` | `UUID` | Non | — | `False` | — |
| `ingestion_run_id` | `UUID` | Non | — | `False` | — |
| `external_record_id` | `VARCHAR(255)` | Oui | — | `False` | — |
| `retrieved_at` | `TIMESTAMP` | Non | `now()` | `False` | — |
| `request_url` | `TEXT` | Oui | — | `False` | — |
| `http_status` | `INTEGER` | Oui | — | `False` | — |
| `payload` | `JSONB` | Non | — | `False` | — |
| `payload_hash` | `VARCHAR(64)` | Non | — | `False` | — |
| `source_updated_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `processing_status` | `VARCHAR(30)` | Non | `'pending'::character varying` | `False` | — |
| `error_message` | `TEXT` | Oui | — | `False` | — |
| `processing_started_at` | `TIMESTAMP` | Oui | — | `False` | — |
| `processing_attempts` | `INTEGER` | Non | `0` | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `ck_source_payload_ck_source_payload_processing_attempts_8f63` | CHECK | `CHECK (processing_attempts >= 0)` |
| `ck_source_payload_http_status_valid` | CHECK | `CHECK (http_status IS NULL OR http_status >= 100 AND http_status <= 599)` |
| `ck_source_payload_processing_status_valid` | CHECK | `CHECK (processing_status::text = ANY (ARRAY['pending'::character varying, 'processing'::character varying, 'processed'::character varying, 'failed'::character varying]::text[]))` |
| `fk_source_payload_ingestion_run_id_ingestion_run` | FOREIGN KEY | `FOREIGN KEY (ingestion_run_id) REFERENCES ops.ingestion_run(id) ON DELETE RESTRICT` |
| `fk_source_payload_source_id_source` | FOREIGN KEY | `FOREIGN KEY (source_id) REFERENCES ops.source(id) ON DELETE RESTRICT` |
| `source_payload_id_not_null` | n | `NOT NULL id` |
| `source_payload_ingestion_run_id_not_null` | n | `NOT NULL ingestion_run_id` |
| `source_payload_payload_hash_not_null` | n | `NOT NULL payload_hash` |
| `source_payload_payload_not_null` | n | `NOT NULL payload` |
| `source_payload_processing_attempts_not_null` | n | `NOT NULL processing_attempts` |
| `source_payload_processing_status_not_null` | n | `NOT NULL processing_status` |
| `source_payload_retrieved_at_not_null` | n | `NOT NULL retrieved_at` |
| `source_payload_source_id_not_null` | n | `NOT NULL source_id` |
| `pk_source_payload` | PRIMARY KEY | `PRIMARY KEY (id)` |
| `source_external_id_payload_hash` | UNIQUE | `UNIQUE (source_id, external_record_id, payload_hash)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `ix_source_payload_ingestion_run_id` | Non | Non | Oui | `CREATE INDEX ix_source_payload_ingestion_run_id ON raw.source_payload USING btree (ingestion_run_id)` |
| `ix_source_payload_pending_claim` | Non | Non | Oui | `CREATE INDEX ix_source_payload_pending_claim ON raw.source_payload USING btree (source_id, retrieved_at, id) WHERE ((processing_status)::text = 'pending'::text)` |
| `ix_source_payload_processing_lease` | Non | Non | Oui | `CREATE INDEX ix_source_payload_processing_lease ON raw.source_payload USING btree (source_id, processing_started_at) WHERE ((processing_status)::text = 'processing'::text)` |
| `ix_source_payload_source_retrieved_at` | Non | Non | Oui | `CREATE INDEX ix_source_payload_source_retrieved_at ON raw.source_payload USING btree (source_id, retrieved_at)` |
| `pk_source_payload` | Oui | Oui | Oui | `CREATE UNIQUE INDEX pk_source_payload ON raw.source_payload USING btree (id)` |
| `source_external_id_payload_hash` | Oui | Non | Oui | `CREATE UNIQUE INDEX source_external_id_payload_hash ON raw.source_payload USING btree (source_id, external_record_id, payload_hash)` |

#### Triggers

Aucun trigger utilisateur.

## Schéma `threat_intel` {#schema-threat_intel}

- Owner : `threat_intel_owner`
- Nombre de tables : **1**

### `threat_intel.alembic_version`

| Information | Valeur |
|---|---|
| Type d'objet | `table` |
| Nombre exact de lignes | 1 |
| Estimation PostgreSQL | -1 |
| Taille totale | 24.00 KiB |
| Taille des données | 8.00 KiB |
| Taille des index | 16.00 KiB |

#### Colonnes

| Colonne | Type | Nullable | Valeur par défaut | Auto-incrément | Commentaire |
|---|---|:---:|---|---|---|
| `version_num` | `VARCHAR(32)` | Non | — | `False` | — |

#### Contraintes

| Nom | Type | Définition |
|---|---|---|
| `alembic_version_version_num_not_null` | n | `NOT NULL version_num` |
| `alembic_version_pkc` | PRIMARY KEY | `PRIMARY KEY (version_num)` |

#### Index

| Nom | Unique | Primaire | Valide | Définition |
|---|:---:|:---:|:---:|---|
| `alembic_version_pkc` | Oui | Oui | Oui | `CREATE UNIQUE INDEX alembic_version_pkc ON threat_intel.alembic_version USING btree (version_num)` |

#### Triggers

Aucun trigger utilisateur.

## Autres objets PostgreSQL

Aucune vue, vue matérialisée, séquence, fonction, procédure ou enum métier détecté.

## Notes de sécurité

- Le document contient uniquement la structure et les statistiques de la base.
- Aucun payload JSON brut n'est extrait.
- Aucun token, mot de passe ou URL de connexion n'est écrit dans les fichiers.
- Les valeurs de `raw.source_payload.payload` ne sont jamais lues.
