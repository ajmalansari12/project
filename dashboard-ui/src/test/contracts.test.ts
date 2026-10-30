import { describe, it, expect } from 'vitest';
import type {
  SecurityVerdict,
  AnalysisJobStatus,
  IncidentStatus,
  ResponseActionStatus,
  DetectionSeverity,
  ComponentAvailability,
  EndpointEventType,
  EndpointEvent,
  DetectionEvidence,
  AnalysisResult,
  HashReputationSummary,
  ApiErrorResponse,
} from '../types/contracts';

describe('Shared TypeScript Contracts', () => {
  it('instantiates valid EndpointEvent structure', () => {
    const event: EndpointEvent = {
      event_id: 'e1d2c3b4-a5f6-4789-8012-3456789abcde',
      event_type: 'file_created',
      timestamp: '2026-10-29T12:00:00Z',
      source_component: 'sensor_fs_watcher',
      file_path: 'C:\\Windows\\System32\\sample.dll',
      file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      process_id: 1044,
      parent_process_id: 4,
      metadata: { size: 4096 },
    };

    expect(event.event_id).toBe('e1d2c3b4-a5f6-4789-8012-3456789abcde');
    expect(event.event_type).toBe('file_created');
  });

  it('instantiates valid DetectionEvidence structure', () => {
    const evidence: DetectionEvidence = {
      evidence_id: 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
      incident_id: 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e',
      source: 'yara_engine',
      indicator: 'rule_malicious_pe',
      severity: 'HIGH',
      description: 'Matched known dropper pattern',
      confidence: 0.95,
      score_contribution: 50.0,
      observed_at: '2026-10-29T12:05:00Z',
    };

    expect(evidence.severity).toBe('HIGH');
    expect(evidence.confidence).toBe(0.95);
  });

  it('instantiates valid AnalysisResult structure', () => {
    const result: AnalysisResult = {
      job_id: 'c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f',
      analysis_status: 'COMPLETED',
      verdict: 'MALICIOUS',
      risk_score: 95.0,
      modules_executed: ['sha256', 'yara'],
      modules_skipped: [],
      modules_failed: [],
      evidence_ids: ['a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d'],
    };

    expect(result.verdict).toBe('MALICIOUS');
    expect(result.risk_score).toBe(95.0);
  });

  it('instantiates valid AnalysisResult with HashReputationSummary', () => {
    const hashRep: HashReputationSummary = {
      file_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      is_known: true,
      verdict: 'MALICIOUS',
      list_type: 'BLOCKLIST',
    };

    const result: AnalysisResult = {
      job_id: 'c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f',
      analysis_status: 'COMPLETED',
      verdict: null,
      risk_score: null,
      modules_executed: ['sha256', 'hash_reputation'],
      modules_skipped: [],
      modules_failed: [],
      evidence_ids: [],
      hash_reputation: hashRep,
    };

    expect(result.verdict).toBeNull();
    expect(result.risk_score).toBeNull();
    expect(result.hash_reputation?.file_hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(result.hash_reputation?.file_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(result.hash_reputation?.is_known).toBe(true);
    expect(result.hash_reputation?.verdict).toBe('MALICIOUS');
    expect(result.hash_reputation?.list_type).toBe('BLOCKLIST');
  });

  it('instantiates valid ApiErrorResponse structure', () => {
    const errorResponse: ApiErrorResponse = {
      error: {
        code: 'VALIDATION_FAILED',
        message: 'Invalid request payload',
        details: { field: 'event_id' },
        request_id: 'req-test-999',
      },
    };

    expect(errorResponse.error.code).toBe('VALIDATION_FAILED');
  });

  it('validates enum union literal types', () => {
    const verdicts: SecurityVerdict[] = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS'];
    const jobStatuses: AnalysisJobStatus[] = ['QUEUED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED'];
    const incidentStatuses: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'];
    const actionStatuses: ResponseActionStatus[] = ['PENDING', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'CANCELLED'];
    const severities: DetectionSeverity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const availabilities: ComponentAvailability[] = [
      'available', 'unavailable', 'degraded', 'disabled', 'not_initialized', 'unknown',
    ];
    const eventTypes: EndpointEventType[] = [
      'file_created', 'file_modified', 'file_renamed', 'file_deleted', 'process_observed', 'canary_triggered',
    ];

    expect(verdicts).toHaveLength(3);
    expect(jobStatuses).toHaveLength(5);
    expect(incidentStatuses).toHaveLength(5);
    expect(actionStatuses).toHaveLength(5);
    expect(severities).toHaveLength(5);
    expect(availabilities).toHaveLength(6);
    expect(eventTypes).toHaveLength(6);
  });

  it('instantiates valid DatasetSampleRecord structure', () => {
    const sample: import('../types/contracts').DatasetSampleRecord = {
      sample_id: 'sample-001',
      sample_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      dataset_name: 'ember',
      dataset_version: '2018',
      target_label: 1,
      split: 'train',
      feature_schema_version: 'ember_pe_v1',
      source_label: 1,
      label_provenance: 'avclass',
      relative_path: 'binaries/sample-001.bin',
      collected_at: '2026-10-29T12:00:00Z',
    };

    expect(sample.target_label).toBe(1);
    expect(sample.sample_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(sample.split).toBe('train');
  });

  it('exposes verified EMBER 2018 release constants', async () => {
    const {
      EMBER_2018_DATASET_NAME,
      EMBER_2018_DATASET_VERSION,
      EMBER_2018_FEATURE_VERSION,
      EMBER_2018_FEATURE_SCHEMA_VERSION,
      EMBER_2018_CANONICAL_FEATURE_DIMENSION,
      EMBER_2018_ARCHIVE_NAME,
      EMBER_2018_ARCHIVE_SHA256,
    } = await import('../types/contracts');

    expect(EMBER_2018_DATASET_NAME).toBe('ember');
    expect(EMBER_2018_DATASET_VERSION).toBe('2018');
    expect(EMBER_2018_FEATURE_VERSION).toBe(2);
    expect(EMBER_2018_FEATURE_SCHEMA_VERSION).toBe('ember_pe_v2');
    expect(EMBER_2018_CANONICAL_FEATURE_DIMENSION).toBe(2381);
    expect(EMBER_2018_ARCHIVE_NAME).toBe('ember_dataset_2018_2.tar.bz2');
    expect(EMBER_2018_ARCHIVE_SHA256).toBe(
      'b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812'
    );
  });

  it('instantiates valid DatasetManifest structure', () => {
    const manifest: import('../types/contracts').DatasetManifest = {
      manifest_id: 'manifest-2018-v1',
      dataset_name: 'ember',
      dataset_version: '2018',
      schema_version: '1.0.0',
      source: 'https://github.com/elastic/ember',
      label_mapping: { '0': 0, '1': 1, '-1': null },
      class_definitions: { '0': 'benign', '1': 'malicious' },
      sample_count: 1000,
      split_counts: { train: 800, validation: 100, test: 100, unassigned: 0 },
      integrity_digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      assumptions_and_limitations: ['Windows PE format only'],
      created_at: '2026-10-29T12:00:00Z',
    };

    expect(manifest.sample_count).toBe(1000);
    expect(manifest.split_counts?.train).toBe(800);
    expect(manifest.label_mapping['-1']).toBeNull();
  });

  it('instantiates valid FeatureVector structure', () => {
    const vector: import('../types/contracts').FeatureVector = {
      sample_id: 'sample-001',
      sample_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      feature_schema_version: 'ember_pe_v1',
      feature_values: [0.1, 0.5, 3.14, null],
      feature_count: 4,
      missing_value_strategy: 'native_nan',
      extraction_duration_ms: 12.5,
    };

    expect(vector.feature_count).toBe(4);
    expect(vector.feature_values).toHaveLength(4);
    expect(vector.missing_value_strategy).toBe('native_nan');
  });

  it('instantiates valid ModelMetadata and DatasetValidationReport structures', () => {
    const metadata: import('../types/contracts').ModelMetadata = {
      model_id: 'sentinel-pe-lightgbm',
      model_version: '1.0.0',
      model_family: 'lightgbm',
      task_type: 'binary_classification',
      dataset_id: 'ember',
      dataset_version: '2018',
      feature_schema_version: 'ember_pe_v1',
      feature_count: 2381,
      label_mapping: { '0': 'BENIGN', '1': 'MALICIOUS' },
      class_order: ['BENIGN', 'MALICIOUS'],
    };

    const report: import('../types/contracts').DatasetValidationReport = {
      is_valid: true,
      total_records: 100,
      valid_record_count: 100,
      invalid_record_count: 0,
      duplicate_digest_count: 0,
      duplicate_digests: [],
      missing_label_count: 0,
      excluded_unlabeled_count: 0,
      split_counts: { train: 80, test: 20 },
      split_overlap_count: 0,
      split_overlap_findings: [],
      errors: [],
      warnings: [],
    };

    expect(metadata.model_family).toBe('lightgbm');
    expect(metadata.feature_count).toBe(2381);
    expect(report.is_valid).toBe(true);
  });
});
