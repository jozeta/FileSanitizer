export type RiskLevel = 'CLEAN' | 'LOW RISK' | 'MEDIUM RISK' | 'HIGH RISK' | 'MALICIOUS';

export type JobState = 'QUEUED' | 'ANALYZING' | 'ANALYZED' | 'SANITIZING' | 'VALIDATING' | 'COMPLETED' | 'FAILED';

export interface Finding {
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  details?: Record<string, any>;
}

export interface RiskAssessment {
  level: RiskLevel;
  score: number;
  reasons: string[];
  recommendation: string;
  suggested_profile: 'minimal' | 'privacy' | 'security' | 'maximum';
  allow_download_original: boolean;
  allow_sanitization: boolean;
}

export interface ClamAVScan {
  scanner: string;
  status: 'CLEAN' | 'MALICIOUS' | 'ERROR' | 'UNAVAILABLE';
  engine_version: string;
  signature_db: string;
  threat_name?: string | null;
  scan_timestamp: string;
}

export interface MetadataField {
  name: string;
  value: string;
  is_sensitive: boolean;
  category: string;
}

export interface StructuredMetadata {
  general: MetadataField[];
  document: MetadataField[];
  location: MetadataField[];
  camera: MetadataField[];
  embedded: MetadataField[];
  total_fields: number;
  sensitive_count: number;
}

export interface UrlItem {
  url: string;
  domain: string;
  protocol: string;
  port: number;
  is_ssrf_safe: boolean;
  ssrf_reason?: string | null;
  risk: string;
  indicators: string[];
  reputation: {
    heuristic: string;
    virus_total: string;
    urlhaus: string;
    safe_browsing: string;
  };
  http_status?: number | null;
  tls_valid: boolean;
  screenshot_available: boolean;
  screenshot_url?: string;
}

export interface SanitizationOptions {
  profile?: string;
  remove_metadata: boolean;
  remove_gps: boolean;
  remove_author: boolean;
  remove_timestamps: boolean;
  remove_comments: boolean;
  remove_embedded_files: boolean;
  remove_macros: boolean;
  remove_javascript: boolean;
  remove_external_links: boolean;
  remove_hyperlinks: boolean;
  reencode_image: boolean;
  flatten_image: boolean;
  convert_to_jpg: boolean;
  convert_to_png: boolean;
  flatten_document: boolean;
  rasterize_pages: boolean;
  convert_to_pdf: boolean;
  strip_active_content: boolean;
  strip_external_resources: boolean;
}

export interface ValidationMetrics {
  file_size: number;
  sha256: string;
  mime_type: string;
  metadata_count: number;
  sensitive_metadata_count?: number;
  urls_count: number;
  has_javascript: boolean;
  has_macros: boolean;
  attachments_count: number;
}

export interface ValidationComparison {
  is_clean: boolean;
  original: ValidationMetrics;
  sanitized: ValidationMetrics;
  clamav_status: string;
  removed_items: string[];
  warnings: string[];
}

export interface JobDetail {
  job_id: string;
  filename: string;
  original_filename: string;
  created_at: string;
  state: JobState;
  progress: number;
  file_size: number;
  mime_type: string;
  category: string;
  signature_description: string;
  hashes?: Record<string, string>;
  clamav?: ClamAVScan;
  risk?: RiskAssessment;
  findings?: Finding[];
  metadata?: StructuredMetadata;
  urls?: UrlItem[];
  validation?: ValidationComparison;
  error_message?: string | null;
}
