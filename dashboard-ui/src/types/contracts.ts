/**
 * Sentinel-EDR Shared TypeScript Contracts
 * 
 * Defines common types, enums, and data models matching the backend Pydantic
 * schemas and the language-neutral JSON Schemas in `shared/schemas/`.
 */

// ============================================================================
// Common Enums & String Literal Unions
// ============================================================================

export type SecurityVerdict = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';

export type HashListType = 'ALLOWLIST' | 'BLOCKLIST' | 'CUSTOM';

export type AnalysisJobStatus =
  | 'QUEUED'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type IncidentStatus =
  | 'OPEN'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED';

export type ResponseActionStatus =
  | 'PENDING'
  | 'IN_PROGRESS'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED';

export type DetectionSeverity =
  | 'INFO'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

export type ComponentAvailability =
  | 'available'
  | 'unavailable'
  | 'degraded'
  | 'disabled'
  | 'not_initialized'
  | 'unknown';

export type EndpointEventType =
  | 'file_created'
  | 'file_modified'
  | 'file_renamed'
  | 'file_deleted'
  | 'process_observed'
  | 'canary_triggered';

// ============================================================================
// Public Data Transfer Interfaces
// ============================================================================

export interface EndpointEvent {
  event_id: string;
  event_type: EndpointEventType;
  timestamp: string; // ISO 8601 UTC timestamp
  source_component: string;
  file_path?: string | null;
  file_hash?: string | null; // SHA-256 64-hex string
  process_id?: number | null;
  parent_process_id?: number | null;
  metadata?: Record<string, unknown>;
}

export interface DetectionEvidence {
  evidence_id: string;
  incident_id: string;
  source: string;
  indicator: string;
  severity: DetectionSeverity;
  description: string;
  observed_value?: string | null;
  confidence?: number | null; // 0.0 - 1.0
  score_contribution?: number | null;
  details?: Record<string, unknown> | null;
  observed_at: string; // ISO 8601 UTC timestamp
  analysis_job_id?: string | null;
}

export interface HashReputationSummary {
  file_hash: string; // Canonical 64-character lowercase SHA-256 hash digest (^[a-f0-9]{64}$)
  is_known: boolean;
  verdict?: SecurityVerdict | null;
  list_type?: HashListType | null;
}

export interface MlDetectionSummary {
  model_id: string;
  model_version: string;
  artifact_hash: string;
  feature_schema: string;
  malicious_probability: number;
  benign_probability: number;
  operating_threshold: number;
  predicted_label: number;
  predicted_class: string;
  inference_duration_ms: number;
  is_degraded?: boolean;
}

export interface AnalysisResult {
  job_id: string;
  analysis_status: AnalysisJobStatus;
  verdict?: SecurityVerdict | null;
  risk_score?: number | null; // 0.0 - 100.0
  modules_executed: string[];
  modules_skipped: string[];
  modules_failed: string[];
  evidence_ids: string[];
  hash_reputation?: HashReputationSummary | null;
  ml_detection?: MlDetectionSummary | null;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  details?: unknown;
  request_id?: string | null;
}

export interface ApiErrorResponse {
  error: ApiErrorDetail;
}

// ============================================================================
// Machine Learning & Dataset Contracts
// ============================================================================

export const EMBER_2018_DATASET_NAME = 'ember';
export const EMBER_2018_DATASET_VERSION = '2018';
export const EMBER_2018_FEATURE_VERSION = 2;
export const EMBER_2018_FEATURE_SCHEMA_VERSION = 'ember_pe_v2';
export const EMBER_2018_CANONICAL_FEATURE_DIMENSION = 2381;
export const EMBER_2018_UPSTREAM_REPOSITORY_URL = 'https://github.com/elastic/ember';
export const EMBER_2018_ARCHIVE_NAME = 'ember_dataset_2018_2.tar.bz2';
export const EMBER_2018_ARCHIVE_URL = 'https://ember.elastic.co/ember_dataset_2018_2.tar.bz2';
export const EMBER_2018_ARCHIVE_SHA256 = 'b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812';

export type DatasetSplit = 'train' | 'validation' | 'test' | 'unassigned';

export type MissingValueStrategy = 'native_nan' | 'zero_fill' | 'mean_impute';

export type ModelFamily = 'lightgbm';

export type TaskType = 'binary_classification';

export interface DatasetSampleRecord {
  sample_id: string;
  sample_hash: string; // Canonical 64-hex lowercase SHA-256 (^[a-f0-9]{64}$)
  dataset_name: string;
  dataset_version: string;
  target_label: 0 | 1;
  split: DatasetSplit;
  feature_schema_version: string;
  source_record_id?: string | null;
  source_label?: number | string | null;
  label_provenance?: string | null;
  relative_path?: string | null;
  collected_at?: string | null; // ISO 8601 UTC timestamp
}

export interface SplitCounts {
  train: number;
  validation: number;
  test: number;
  unassigned: number;
}

export interface DatasetManifest {
  manifest_id: string;
  dataset_name: string;
  dataset_version: string;
  schema_version: string;
  source: string;
  label_mapping: Record<string, number | null>;
  class_definitions: Record<string, string>;
  sample_count: number;
  split_counts?: SplitCounts | null;
  excluded_unlabeled_count?: number | null;
  integrity_digest?: string | null;
  assumptions_and_limitations?: string[];
  created_at: string; // ISO 8601 UTC timestamp
}

export interface FeatureVector {
  sample_id: string;
  sample_hash: string; // Canonical 64-hex lowercase SHA-256
  feature_schema_version: string;
  feature_values: Array<number | null>;
  feature_count: number;
  missing_value_strategy: MissingValueStrategy;
  extraction_duration_ms?: number | null;
  feature_names?: string[] | null;
}

export interface ModelMetrics {
  roc_auc?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1_score?: number | null;
  false_positive_rate?: number | null;
  evaluation_split?: 'test' | 'validation' | null;
  [key: string]: unknown;
}

export interface ModelMetadata {
  model_id: string;
  model_version: string;
  model_family: ModelFamily;
  task_type: TaskType;
  dataset_id: string;
  dataset_version: string;
  feature_schema_version: string;
  feature_count: number;
  label_mapping: Record<string, string>;
  class_order: string[];
  training_config?: Record<string, unknown> | null;
  artifact_format?: 'ONNX' | 'LightGBM_Binary' | 'LightGBM_Text' | null;
  artifact_hash?: string | null;
  metrics?: ModelMetrics | null;
  created_at?: string | null;
  evaluated_at?: string | null;
}

export interface DatasetValidationReport {
  is_valid: boolean;
  total_records: number;
  valid_record_count: number;
  invalid_record_count: number;
  duplicate_digest_count: number;
  duplicate_digests: string[];
  missing_label_count: number;
  excluded_unlabeled_count: number;
  split_counts: Record<string, number>;
  split_overlap_count: number;
  split_overlap_findings: Array<{
    sample_hash: string;
    splits: string[];
    sample_ids: string[];
  }>;
  errors: string[];
  warnings: string[];
}
