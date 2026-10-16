export type RiskLevel = 'CLEAN' | 'LOW RISK' | 'MEDIUM RISK' | 'HIGH RISK' | 'MALICIOUS';

export type JobState = 'QUEUED' | 'ANALYZING' | 'ANALYZED' | 'SANITIZING' | 'VALIDATING' | 'COMPLETED' | 'FAILED';

export interface Finding {
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  details?: Record<string, any>;
}

export interface RiskSubscore {
  factor: string;
  category: string;
  subscore: number;
  points?: number;
  reason: string;
}

export interface RiskAssessment {
  level: RiskLevel;
  score: number;
  reasons: string[];
  recommendation: string;
  suggested_profile: 'minimal' | 'privacy' | 'security' | 'maximum';
  allow_download_original: boolean;
  allow_sanitization: boolean;
  breakdown?: RiskSubscore[];
  calculation_formula?: string;
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

export interface ForensicAnomaly {
  type: string;
  title: string;
  details: string;
  severity: string;
}

export interface StructuredMetadata {
  general: MetadataField[];
  document: MetadataField[];
  location: MetadataField[];
  camera: MetadataField[];
  embedded: MetadataField[];
  forensic_anomalies?: ForensicAnomaly[];
  total_fields: number;
  sensitive_count: number;
}

export interface ExtractedCodeModule {
  name: string;
  stream?: string;
  code: string;
}

export interface ExtractedCode {
  type: string;
  language: string;
  code: string;
  modules?: ExtractedCodeModule[];
}

export interface VirusTotalResult {
  configured: boolean;
  queried: boolean;
  found?: boolean;
  web_link: string;
  sha256?: string;
  positives?: number;
  total_engines?: number;
  malicious_count?: number;
  suspicious_count?: number;
  reputation?: number;
  meaningful_name?: string;
  type_description?: string;
  suggested_threat_label?: string;
  threat_category?: string;
  tags?: string[];
  times_submitted?: number;
  flagged_engines?: Array<{ engine: string; category: string; result: string }>;
}

export interface HybridAnalysisResult {
  configured?: boolean;
  status?: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN' | 'NOT_CONFIGURED' | 'AUTH_ERROR' | 'ERROR' | string;
  verdict?: string;
  threat_score?: number;
  malware_family?: string;
  environment?: string;
  av_detect_rate?: number;
  mitre_attck?: string[];
  report_url?: string;
  error?: string;
}

export interface ThreatFoxResult {
  configured?: boolean;
  status?: 'MALICIOUS' | 'CLEAN' | 'ERROR' | 'NOT_CHECKED' | string;
  malware?: string;
  threat_type?: string;
  confidence?: number;
  matches_count?: number;
  search_url?: string;
  error?: string;
}

export interface MalwareBazaarResult {
  configured?: boolean;
  status?: 'MALICIOUS' | 'CLEAN' | 'ERROR' | 'NOT_CHECKED' | string;
  signature?: string;
  file_type?: string;
  reporter?: string;
  first_seen?: string;
  tags?: string[];
  delivery_method?: string;
  search_url?: string;
  error?: string;
}

export interface CirclHashlookupResult {
  configured?: boolean;
  status?: 'BENIGN_KNOWN' | 'UNKNOWN' | 'ERROR' | 'NOT_CHECKED' | string;
  is_nsrl?: boolean;
  file_name?: string;
  vendor?: string;
  search_url?: string;
  details?: Record<string, any>;
  error?: string;
}

export interface AlienVaultOTXResult {
  configured?: boolean;
  status?: 'MALICIOUS' | 'CLEAN' | 'AUTH_ERROR' | 'RATE_LIMITED' | 'ERROR' | 'NOT_CONFIGURED' | 'NOT_CHECKED' | string;
  pulse_count?: number;
  pulse_names?: string[];
  tags?: string[];
  search_url?: string;
  error?: string;
}

export interface YaraMatch {
  rule_id: string;
  rule_name: string;
  identifier: string;
  description: string;
  severity: string;
  target_format: string;
  tags: string[];
  strings?: Array<{ identifier: string; offset: number; matched_data: string }>;
}

export interface YaraResult {
  matches_count: number;
  matches: YaraMatch[];
}

export interface TlsCertificateInfo {
  valid: boolean;
  tls_version?: string;
  cipher?: string;
  issuer?: string | Record<string, string>;
  subject?: string | Record<string, string>;
  valid_from?: string;
  valid_to?: string;
  days_remaining?: number;
  is_expired?: boolean;
  error?: string;
  serial_number?: string;
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
    threatfox?: string;
    urlscan?: string;
    abuseipdb?: string;
    alienvault_otx?: string;
    virus_total_details?: {
      malicious: number;
      suspicious: number;
      harmless: number;
      total: number;
      reputation: number;
      categories?: string[];
      tags?: string[];
    };
    abuseipdb_details?: {
      abuse_confidence_score: number;
      total_reports: number;
      isp?: string;
      domain?: string;
      country_code?: string;
      is_whitelisted?: boolean;
      error?: string;
    };
    alienvault_details?: {
      pulse_count: number;
      threat_score: number;
      tags?: string[];
      error?: string;
    };
  };
  http_status?: number | null;
  redirect_url?: string | null;
  is_shortener?: boolean;
  target_analysis?: UrlItem | null;
  tls_valid: boolean;
  certificate?: TlsCertificateInfo;
  screenshot_available: boolean;
  screenshot_url?: string;
  vt_web_link?: string;
}

export interface ExternalConnectionPolicy {
  allow_all_external: boolean;
  allow_http_status_and_redirects: boolean;
  allow_screenshots: boolean;
  allow_tls_inspection: boolean;
  allow_threat_intel_lookups: boolean;
  allow_geolocation_lookups: boolean;
  allow_clamav_official_updates: boolean;
}

export interface StatisticsData {
  total_files_analyzed: number;
  total_files_sanitized: number;
  malware_detected_count: number;
  high_risk_count: number;
  clean_count: number;
  total_bytes_processed?: number;
  severity_distribution?: Record<string, number>;
  daily_uploads?: Record<string, number>;
  last_30_days?: Array<{ date: string; day: string; count: number }>;
  categories_count: Record<string, number>;
  findings_breakdown: Record<string, number>;
  sanitization_formats: Record<string, number>;
}

export interface YaraRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  target_format: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
  rule_text: string;
}

export interface ClamAVDefinition {
  name: string;
  size_bytes: number;
  modified: string;
  days_old?: number;
  days_old_text?: string;
  type: string;
}

export interface ClamAVInfo {
  status: string;
  host: string;
  port: number;
  engine_version: string;
  db_version: string;
  db_date: string;
  db_days_old?: number;
  db_days_old_text?: string;
  definition_dir: string;
  definitions: ClamAVDefinition[];
  last_checked: string;
  update_check?: {
    success: boolean;
    newer_available: boolean;
    local_version?: number;
    remote_version?: number;
    remote_date?: string;
    remote_signatures?: number;
    message?: string;
    checked_at?: string;
    error?: string;
  };
  community_signatures?: Record<string, {
    name: string;
    installed: boolean;
    description: string;
    url: string;
    files_detected?: string[];
  }>;
}

export interface WarningRule {
  id: string;
  name?: string;
  pattern: string;
  is_regex: boolean;
  severity: 'informational' | 'info' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  enabled: boolean;
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

export interface EmailTransitHop {
  hop_number: number;
  from_host: string;
  by_host: string;
  ip: string;
  protocol: string;
  timestamp: string;
  delay_seconds?: number | null;
  country: string;
  city: string;
  asn: string;
  is_private: boolean;
  raw_header: string;
}

export interface EmailAttachmentReputation {
  circl?: {
    status?: string;
    is_nsrl?: boolean;
    file_name?: string;
    vendor?: string;
  };
  threatfox?: {
    status?: string;
    malware?: string;
    threat_type?: string;
  };
  virustotal?: {
    positives?: number;
    total_engines?: number;
    web_link?: string;
    status?: string;
  };
  hybrid_analysis?: HybridAnalysisResult;
}

export interface EmailAttachment {
  index: number;
  filename: string;
  saved_filename?: string;
  saved_path?: string;
  content_type: string;
  size_bytes: number;
  md5: string;
  sha256: string;
  is_dangerous: boolean;
  has_macros: boolean;
  inner_files?: Array<{ filename: string; size: number; date_time?: number[]; is_dangerous: boolean }>;
  reputation?: EmailAttachmentReputation;
}

export interface EmailSenderAnalysis {
  display_name: string;
  from_address: string;
  from_domain: string;
  reply_to_address: string;
  reply_to_domain: string;
  return_path_address: string;
  return_path_domain: string;
  is_mismatched_reply_to: boolean;
  is_mismatched_return_path: boolean;
  is_freemail: boolean;
  is_punycode: boolean;
  display_name_spoofed: boolean;
  impersonated_brand?: string | null;
  has_homoglyphs?: boolean;
  homoglyphs_details?: string[];
  is_vip_impersonation?: boolean;
  vip_title?: string | null;
  sender_domain_intelligence?: any;
}

export interface EmailAuthentication {
  spf: { status: string; raw?: string };
  dkim: { status: string; domain?: string; has_signature: boolean };
  dmarc: { status: string; policy?: string };
  alignment?: {
    from_domain?: string;
    return_path_domain?: string;
    dkim_domain?: string;
    spf_aligned?: boolean;
    dkim_aligned?: boolean;
    dmarc_aligned?: boolean;
  };
  arc?: { present: boolean; status: string };
  overall_trust: string;
}

export interface EmailInfo {
  headers: Record<string, string>;
  raw_email?: string;
  raw_headers?: string;
  all_headers?: Array<{ name: string; value: string }>;
  subject: string;
  from: string;
  to?: string;
  cc?: string;
  date?: string;
  message_id?: string;
  reply_to?: string;
  return_path?: string;
  sender_ips: string[];
  sender_analysis?: EmailSenderAnalysis;
  authentication?: EmailAuthentication;
  transit_hops?: EmailTransitHop[];
  body_plain?: string;
  body_plain_snippet?: string;
  body_html_sanitized?: string;
  has_html: boolean;
  tracking_pixels?: Array<{ url: string; reason: string; width?: string; height?: string }>;
  tracking_pixel_count?: number;
  deceptive_links?: Array<{
    displayed_text: string;
    claimed_destination: string;
    actual_destination: string;
    destination_host: string;
  }>;
  phishing_keywords?: string[];
  recipients_details?: Array<{ name?: string; email?: string; type?: string; addrtype?: string }>;
  ole_msg_metadata?: Record<string, any>;
  attachments: EmailAttachment[];
  attachment_count: number;
  urls: string[];
  thread_hijacking?: {
    is_reply_subject: boolean;
    has_in_reply_to: boolean;
    has_references: boolean;
    suspected_hijacking: boolean;
  };
  attachment_graph?: Array<{
    source: string;
    target: string;
    relationship: string;
    details?: string;
  }>;
}

export interface BinarySection {
  name: string;
  virtual_address: string;
  virtual_size: number;
  raw_offset: string;
  raw_size: number;
  entropy: number;
  is_wx: boolean;
  is_entry_point: boolean;
  is_packed: boolean;
  flags: string[];
}

export interface BinaryImportFunction {
  name: string;
  ordinal?: number;
  address?: string;
  is_suspicious: boolean;
  severity?: string;
  description?: string;
}

export interface BinaryExportFunction {
  name: string;
  ordinal?: number;
  address?: string;
}

export interface BinaryResource {
  type: string;
  name: string;
  language?: number;
  offset: string;
  size: number;
  size_percent?: number;
  entropy: number;
  is_embedded_pe: boolean;
  is_embedded_archive: boolean;
  is_high_entropy: boolean;
}

export interface BinaryStrings {
  total_count: number;
  network: string[];
  file_paths: string[];
  registry: string[];
  commands: string[];
  all_sample: string[];
}

export interface DecompiledVariable {
  name: string;
  type: string;
  scope?: string;
  inferred_from?: string;
}

export interface DecompiledParameter {
  type: string;
  name: string;
}

export interface DecompiledFunction {
  function_name: string;
  address: string;
  signature: string;
  return_type: string;
  parameters: DecompiledParameter[];
  variables: DecompiledVariable[];
  code: string;
  confidence: number;
  basic_blocks_count: number;
  has_loops: boolean;
  has_conditionals: boolean;
  api_calls: string[];
  suspicious_constructs: string[];
  inst_to_lines?: Record<number, number[]>;
  line_to_insts?: Record<number, number[]>;
}

export interface XrefEntry {
  from_address: string;
  from_function: string;
  target?: string;
  target_address?: string;
  instruction: string;
  ref_type: 'CODE_CALL' | 'CONDITIONAL_JUMP' | 'UNCONDITIONAL_JUMP' | 'DATA_READ' | 'DATA_WRITE' | 'STRING_REF' | 'API_CALL' | string;
  direction: 'incoming' | 'outgoing';
  description: string;
}

export interface XrefData {
  total_xrefs: number;
  code_xrefs_count: number;
  data_xrefs_count: number;
  string_xrefs_count: number;
  target_to_xrefs: Record<string, XrefEntry[]>;
  source_to_outgoing: Record<string, XrefEntry[]>;
  hotspots: Array<{ target: string; references_count: number; callers: string[] }>;
}

export interface CallGraphNode {
  id: string;
  label: string;
  address: string;
  node_type: 'ENTRY_POINT' | 'INTERNAL' | 'IMPORT_API' | 'RESOLVED_HASH' | 'EXPORT' | string;
  risk: 'critical' | 'high' | 'medium' | 'info';
  instruction_count: number;
  suspicious_flags: string[];
  is_root: boolean;
  in_degree: number;
  out_degree: number;
}

export interface CallGraphEdge {
  id: string;
  source: string;
  target: string;
  call_type: 'CALL' | 'JUMP' | 'DYNAMIC_RESOLVE' | string;
  instruction_address?: string;
  count: number;
}

export interface CallGraphData {
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
  metrics: {
    total_functions: number;
    total_calls: number;
    has_recursion: boolean;
    high_risk_nodes_count: number;
  };
}

export interface ApiHashMatch {
  address?: string;
  offset?: string;
  instruction?: string;
  hash_hex: string;
  resolved_api: string;
  dll: string;
  algorithm: 'ROR13' | 'CRC32' | 'FNV-1a' | 'MurmurHash3' | 'SDBM' | 'DJB2' | string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  mitre_tactic?: string;
  confidence?: string;
}

export interface BinaryInfo {
  format: string;
  architecture: string;
  subsystem: string;
  entry_point?: string;
  is_packed: boolean;
  packers: string[];
  compilers?: string[];
  packers_and_compilers?: {
    compiler?: string;
    packer?: string | null;
    is_packed?: boolean;
    detection_details?: string[];
  };
  detected_tools?: Array<{ tool_id: string; compiler: string; count: number; name: string }>;
  digital_signature: string;
  digital_signature_valid?: boolean;
  certificate_details?: {
    subject?: string;
    issuer?: string;
    serial_number?: string;
    digest_algorithm?: string;
  };
  dos_header?: Record<string, any>;
  dos_stub?: {
    size_bytes: number;
    has_custom_stub: boolean;
    stub_message: string;
  };
  file_header?: {
    machine: string;
    machine_hex: string;
    number_of_sections: number;
    timestamp: string;
    time_date_stamp_raw: number;
    characteristics_hex: string;
    characteristics: string[];
  };
  optional_header?: {
    magic: string;
    magic_hex: string;
    linker_version: string;
    size_of_code: number;
    size_of_initialized_data: number;
    size_of_uninitialized_data: number;
    address_of_entry_point: string;
    entry_point_section: string;
    image_base: string;
    section_alignment: string;
    file_alignment: string;
    operating_system_version: string;
    image_version: string;
    subsystem_version: string;
    size_of_image: number;
    size_of_headers: number;
    checksum: string;
    checksum_calculated: string;
    checksum_verified: boolean;
    subsystem: string;
    dll_characteristics: string;
    dll_characteristics_flags: string[];
    data_directories: Array<{
      index: number;
      name: string;
      virtual_address: string;
      size: number;
      present: boolean;
    }>;
  };
  sections?: BinarySection[];
  sections_count?: number;
  size_analysis?: {
    physical_size: number;
    declared_virtual_size: number;
    headers_size: number;
    sections_raw_total: number;
    has_overlay: boolean;
    overlay_offset: string;
    overlay_size: number;
    overlay_entropy: number;
  };
  imports?: Record<string, BinaryImportFunction[]>;
  import_libraries_count?: number;
  total_imports_count?: number;
  suspicious_apis?: Array<{
    api: string;
    dll: string;
    severity: string;
    description: string;
  }>;
  exports?: BinaryExportFunction[];
  resources?: BinaryResource[];
  resource_types_count?: number;
  abnormal_resources?: string[];
  strings?: BinaryStrings;
  urls?: string[];
  imphash?: string | null;
  rich_header_hash?: string | null;
  rich_header?: {
    md5?: string;
    tools?: Array<{ tool_id: number; version: number; count: number; name?: string; compiler?: string }>;
  };
  disassembly?: {
    entry_point: string;
    instructions: Array<{ address: string; mnemonic: string; op_str: string; bytes: string }>;
    suspicious_patterns: string[];
  };
  decompilation?: DecompiledFunction;
  anti_analysis?: {
    anti_debugging: string[];
    timing_evasion: string[];
    anti_vm: string[];
  };
  authenticode?: {
    is_signed: boolean;
    status?: string;
    trust_status?: string;
    signer_name?: string;
    has_valid_chain?: boolean;
    table_offset?: string;
    table_size?: number;
    declared_length?: number;
    revision?: string;
    certificate_type?: string;
    has_timestamp?: boolean;
    timestamp_type?: string | null;
    anomalies?: string[];
    certificates_count?: number;
    digest_algorithm?: string;
    certificates?: Array<{
      index?: number;
      role?: string;
      display_name?: string;
      subject?: {
        common_name?: string;
        organization?: string;
        country?: string;
        rfc4514?: string;
      };
      issuer?: {
        common_name?: string;
        organization?: string;
        country?: string;
        rfc4514?: string;
        display?: string;
      };
      serial_number?: string;
      valid_from?: string;
      valid_to?: string;
      is_expired?: boolean;
      is_not_yet_valid?: boolean;
      is_self_signed?: boolean;
      signature_algorithm?: string;
      sha256_fingerprint?: string;
      sha1_fingerprint?: string;
      anomalies?: string[];
    }>;
  };
  elf_mitigations?: {
    nx: boolean;
    pie: boolean;
    relro: string;
    stack_canary: boolean;
    stripped: boolean;
  };
  shellcode?: {
    is_shellcode: boolean;
    architecture: string;
    mode: number;
    confidence: number;
    total_bytes: number;
    nop_sled: {
      detected: boolean;
      length: number;
      offset: number;
    };
    heuristics: {
      has_get_eip: boolean;
      has_peb_traversal: boolean;
      has_direct_syscalls: boolean;
      has_api_hashing: boolean;
      has_egg_hunter: boolean;
      has_stack_strings: boolean;
      has_socket_call: boolean;
      has_fpu_routine: boolean;
    };
    detected_features: string[];
    resolved_api_hashes: Array<{
      hash: string;
      offset: string;
      function: string;
      library: string;
      description: string;
    }>;
    stack_strings: string[];
    network_indicators: Array<{
      ip: string;
      port: number;
      offset: string;
    }>;
    suspicious_instructions: Array<{
      address: string;
      instruction: string;
      note: string;
    }>;
    disassembly: Array<{
      address: string;
      mnemonic: string;
      op_str: string;
      bytes: string;
      is_suspicious?: boolean;
      note?: string;
    }>;
  };
  xrefs?: XrefData;
  call_graph?: CallGraphData;
  api_hashing?: ApiHashMatch[];
}

export interface MitreAttackItem {
  technique_id: string;
  technique_name: string;
  tactic_id: string;
  tactic_name: string;
  url: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  evidence: string[];
}

export interface ScriptSuspiciousPattern {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  count: number;
  description: string;
  sample_lines: number[];
}

export interface ScriptMatchedLine {
  line: number;
  pattern: string;
  match: string;
  severity: string;
}

export interface ScriptB64Block {
  encoded: string;
  decoded_preview: string;
  length: number;
}

export interface ScriptTriageInfo {
  script_type: string;
  entropy: number;
  lines_count: number;
  characters_count: number;
  detected_patterns: ScriptSuspiciousPattern[];
  matched_lines: ScriptMatchedLine[];
  b64_blocks: ScriptB64Block[];
  urls: string[];
  risk_score: number;
  is_webshell: boolean;
  has_lolbins: boolean;
  lolbin_matches: string[];
  code_modules: Array<{ name: string; code: string }>;
  dangerous_apis?: Array<{
    category: string;
    api_title: string;
    severity: string;
    description: string;
    count: number;
    matched_sample: string;
    lines: number[];
  }>;
  hta_details?: {
    is_hta: boolean;
    application_tag: Record<string, string>;
    windowstate: string;
    is_stealth_window: boolean;
    html_structure: {
      has_forms: boolean;
      has_passwords: boolean;
      iframes: string[];
      external_resources: string[];
    };
    css_analysis: {
      style_blocks_count: number;
      has_hidden_elements: boolean;
      hidden_techniques: string[];
    };
    script_blocks: {
      vbscript_count: number;
      javascript_count: number;
      inline_handlers_count: number;
      vbscript_snippets: Array<{ start_line: number; lines_count: number; preview: string; code: string }>;
      javascript_snippets: Array<{ start_line: number; lines_count: number; preview: string; code: string }>;
      inline_handlers: Array<{ event: string; handler: string }>;
    };
    activex_objects: string[];
    lolbins_invoked: string[];
  };
}

export interface JobDetail {
  job_id: string;
  filename: string;
  original_filename: string;
  created_at: string;
  state: JobState;
  progress: number;
  current_step?: number;
  current_step_label?: string;
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
  extracted_code?: ExtractedCode;
  virustotal?: VirusTotalResult;
  hybrid_analysis?: HybridAnalysisResult;
  threatfox?: ThreatFoxResult;
  malwarebazaar?: MalwareBazaarResult;
  circl?: CirclHashlookupResult;
  yara?: YaraResult;
  thumbnail_available?: boolean;
  thumbnail_url?: string;
  validation?: ValidationComparison;
  is_password_protected?: boolean;
  is_unlocked?: boolean;
  unlock_password?: string | null;
  email_info?: EmailInfo;
  binary_info?: BinaryInfo;
  script_triage?: ScriptTriageInfo;
  mitre_attack?: MitreAttackItem[];
  embedded_files?: EmbeddedFileItem[];
  deobfuscation?: DeobfuscationResult;
  alienvault_otx?: AlienVaultOTXResult;
  entropy_profile?: EntropyProfile;
  domain_info?: DomainIntelligence;
  extension_info?: ExtensionTriageInfo;
  ai_image_provenance?: AIImageProvenance;
  applescript_info?: AppleScriptTriageInfo;
  office_info?: OfficeTriageInfo;
  pdf_info?: PdfTriageInfo;
  image_info?: ImageTriageInfo;
  jar_info?: JarTriageInfo;
  anti_analysis?: AntiAnalysisInfo;
  similar_samples?: SimilarSampleMatch[];
  cdr_diff?: CdrDiffInfo;
  entity_graph?: EntityGraphData;
  reanalysis_intel_diff?: ReanalysisIntelDiff;
  pcap_info?: PcapInfo;
  shellcode_info?: any;
  hta_info?: any;
  evtx_info?: EvtxInfo;
  lnk_info?: LnkInfo;
  apk_info?: ApkAnalysisData;
  java_info?: JavaAnalysisData;
  detection_rules?: DetectionRules;
  telemetry?: JobTelemetry;
  enriched_iocs?: Record<string, EnrichedIocItem>;
  error_message?: string | null;
}

export interface StepTiming {
  step: number;
  name: string;
  duration_ms: number;
  status: 'success' | 'skipped' | 'failed' | string;
  details?: string;
}

export interface NetworkTelemetry {
  external_lookups_count: number;
  services_contacted: string[];
  urls_inspected: number;
}

export interface JobTelemetry {
  started_at: string;
  completed_at: string;
  total_duration_ms: number;
  steps: StepTiming[];
  checks_executed: string[];
  disabled_checks: string[];
  network_telemetry: NetworkTelemetry;
  pipeline_errors: string[];
}

export interface EvtxTimelineEvent {
  timestamp: string;
  event_id: number;
  provider?: string;
  event_name?: string;
  category?: string;
  channel?: string;
  computer?: string;
  user?: string;
  summary?: string;
  description?: string;
  severity: string;
  is_monitored?: boolean;
  is_threat?: boolean;
  threat_reason?: string;
  command_line?: string;
  process_name?: string;
  process_id?: string;
  parent_process?: string;
  parent_process_id?: string;
  service_name?: string;
  task_name?: string;
  script_text?: string;
  share_name?: string;
  relative_target_name?: string;
  access_mask?: string;
  access_list?: string;
  ip_address?: string;
  ip_port?: string;
  logon_type?: string;
  status_code?: string;
  source_file?: string;
  decoded_command?: string;
  powershell_decoded?: any;
  ps_decoded_info?: any;
  details?: Record<string, any>;
}

export interface EvtxThreatItem {
  event_id?: number;
  timestamp?: string;
  category?: string;
  title?: string;
  description?: string;
  severity?: string;
  threat_reason?: string;
  command_line?: string;
  decoded_command?: string;
  powershell_decoded?: any;
  ps_decoded_info?: any;
  process_name?: string;
  image?: string;
  user?: string;
  parent_process?: string;
  is_lolbin?: boolean;
  is_payload_drop?: boolean;
  details?: Record<string, any>;
}

export interface EvtxDesktopStorylineItem {
  id: string;
  timestamp: string;
  category: 'logon' | 'usb' | 'file_access' | 'execution' | 'defender_tampering' | 'print' | 'log_cleared' | 'logoff' | string;
  title: string;
  description: string;
  user: string;
  computer: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  icon: string;
  event_ids: number[];
  details?: Record<string, any>;
}

export interface EvtxUsbDevice {
  device_name: string;
  vendor: string;
  serial_number: string;
  drive_letter: string;
  status: 'Mounted' | 'Ejected' | string;
  timestamp: string;
  user: string;
  computer: string;
  event_id: number;
}

export interface EvtxFileAccessRecord {
  file_path: string;
  filename: string;
  file_category: 'Documents' | 'Keys & Passwords' | 'Archives' | 'Source Code' | 'Executables' | 'General File' | string;
  operation: 'Read' | 'Write / Modify' | 'Delete' | 'Execute' | string;
  access_mask?: string;
  user: string;
  process: string;
  computer: string;
  timestamp: string;
  is_admin_share: boolean;
  share_name?: string;
  is_sensitive: boolean;
}

export interface EvtxPrintRecord {
  document_name: string;
  pages: number;
  size_bytes: number;
  printer: string;
  port?: string;
  user: string;
  client_machine?: string;
  timestamp: string;
  is_bulk_print: boolean;
  is_sensitive: boolean;
}

export interface EvtxRdpSession {
  user: string;
  client_ip: string;
  client_name: string;
  target_host: string;
  status: 'Authenticated' | 'Active Session' | 'Disconnected' | 'Reconnected' | string;
  timestamp: string;
  event_id: number;
}

export interface EvtxDeobfuscatedCommand {
  raw_command: string;
  deobfuscated_command: string;
  is_obfuscated: boolean;
  obfuscation_types: string[];
  flagged_tokens: string[];
  user: string;
  process: string;
  timestamp: string;
  event_id: number;
  steps: string[];
}

export interface EvtxInfo {
  total_records: number;
  files_parsed?: string[];
  time_range: {
    earliest: string | null;
    latest: string | null;
  };
  event_id_distribution: Record<string, number>;
  sensitive_event_counts: Record<string, number>;
  unique_users: string[];
  unique_computers: string[];
  unique_ips: string[];
  threats: {
    anti_forensics?: EvtxThreatItem[];
    ransomware?: EvtxThreatItem[];
    privilege_escalation?: EvtxThreatItem[];
    brute_force?: EvtxThreatItem[];
    lateral_movement?: EvtxThreatItem[];
    process_creation?: EvtxThreatItem[];
    powershell?: EvtxThreatItem[];
    services_and_tasks?: EvtxThreatItem[];
    network_connections?: EvtxThreatItem[];
  };
  timeline: EvtxTimelineEvent[];
  timeline_events?: EvtxTimelineEvent[];
  desktop_storyline?: EvtxDesktopStorylineItem[];
  usb_history?: EvtxUsbDevice[];
  file_access_audit?: EvtxFileAccessRecord[];
  print_audit?: EvtxPrintRecord[];
  rdp_sessions?: EvtxRdpSession[];
  deobfuscated_commands?: EvtxDeobfuscatedCommand[];
}

export interface AntiAnalysisTechnique {
  category: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  evidence: string;
  mitre_id?: string;
}

export interface AntiAnalysisInfo {
  evasion_detected: boolean;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | string;
  highest_severity: string;
  techniques_count: number;
  techniques: AntiAnalysisTechnique[];
  summary: string;
}

export interface OfficeTriageInfo {
  has_macros: boolean;
  macro_details?: Array<{ type: string; keyword: string; description: string }>;
  macro_modules?: Array<{ name: string; stream: string; code: string }>;
  vba_capabilities?: Record<string, Array<string | { label: string; count: number; samples?: string[] }>>;
  vba_stomping?: { is_stomped: boolean; details?: string[] };
  vba_purging?: { is_purged: boolean; details?: string[] };
  xlm_macros?: { has_xlm_macros: boolean; details?: string[] };
  rtf_exploits?: { is_rtf: boolean; has_exploits: boolean; details?: string[] };
  ole_forensics?: Record<string, any>;
  has_activex?: boolean;
  activex_objects?: string[];
  has_ole_objects?: boolean;
  ole_objects?: string[];
  has_external_relationships?: boolean;
  remote_templates?: Array<string | { source?: string; target: string; type?: string }>;
  has_embedded_files?: boolean;
  embedded_files?: string[];
  metadata?: Record<string, any>;
  urls?: string[];
  excel_analysis?: {
    very_hidden_sheets?: Array<{ name: string; sheet_id: string; state: string }>;
    hidden_sheets?: Array<{ name: string; sheet_id: string; state: string }>;
    all_sheets?: Array<{ name: string; sheet_id: string; state: string }>;
    protected_sheets?: string[];
    power_query_queries?: Array<{ source: string; matched_patterns: string[]; snippet?: string }>;
    hidden_rows_cols?: number;
  };
  powerpoint_analysis?: {
    hover_actions?: Array<{ slide: string; action: string; raw?: string }>;
    click_actions?: Array<{ slide: string; action: string; raw?: string }>;
    hidden_slides?: string[];
    slide_count?: number;
  };
}

export interface PdfTokenOccurrence {
  token: string;
  raw_token: string;
  is_obfuscated: boolean;
  snippet: string;
  extracted_value?: string;
  threat_summary?: string;
  xref?: number | null;
}

export interface PdfTokenDetail {
  token: string;
  count: number;
  obfuscated_count: number;
  obfuscated_samples?: string[];
  threat_summary?: string;
  occurrences: PdfTokenOccurrence[];
}

export interface PdfObjectItem {
  xref: number;
  type: string;
  is_stream: boolean;
  filter: string;
  size: number;
  is_suspicious: boolean;
  suspicious_reason?: string;
  raw_dict?: string;
  stream_text?: string;
  stream_hex?: string;
  is_text?: boolean;
  tokens?: string[];
}

export interface PdfStreamInspection {
  job_id: string;
  xref: number;
  is_stream: boolean;
  size: number;
  raw_dict: string;
  is_text: boolean;
  text_content: string;
  b64_content: string;
  hex_dump: string;
}

export interface PdfTriageInfo {
  is_password_protected?: boolean;
  is_unlocked?: boolean;
  unlock_password?: string | null;
  page_count?: number;
  pdfid?: Record<string, number>;
  pdfid_counts?: Record<string, number>;
  pdfid_tags?: Record<string, number>;
  pdfid_token_details?: Record<string, PdfTokenDetail>;
  obfuscated_tags?: Record<string, number>;
  obfuscated_samples?: Record<string, string[]>;
  has_javascript?: boolean;
  has_launch?: boolean;
  has_open_action?: boolean;
  has_embedded_files?: boolean;
  embedded_files?: string[];
  eof_count?: number;
  incremental_updates?: number;
  javascript_streams?: Array<{ stream_id: number; size: number; code: string }>;
  extracted_code?: ExtractedCode;
  metadata?: Record<string, any>;
  pdf_objects?: PdfObjectItem[];
  total_objects?: number;
  total_streams?: number;
  filter_counts?: Record<string, number>;
  pdf_version?: string;
  is_linearized?: boolean;
}

export interface ImageTriageInfo {
  format?: string;
  width?: number;
  height?: number;
  aspect_ratio?: string;
  color_mode?: string;
  bit_depth?: number;
  compression?: string;
  has_exif?: boolean;
  exif_data?: Record<string, any>;
  gps?: { latitude?: number; longitude?: number; location_name?: string };
  author_info?: Record<string, any>;
  ela_score?: number;
  ela_tampered?: boolean;
  steganography_detected?: boolean;
  lsb_chi_square?: number;
  steganography?: {
    sampled_pixels?: number;
    sampled_bits?: number;
    overall_lsb_entropy?: number;
    channel_entropy?: { red?: number; green?: number; blue?: number };
    bitplane_analysis?: {
      plane0_lsb_entropy?: number;
      plane1_entropy?: number;
      entropy_jump?: number;
    };
    sample_pair_transition_rate?: number;
    chi_square?: number;
    stego_suspicious?: boolean;
    confidence?: string;
  };
  overlay?: {
    has_overlay: boolean;
    offset?: string;
    offset_dec?: number;
    size?: number;
    percent_of_file?: number;
    entropy?: number;
    type?: string;
    preview_hex?: string;
    preview_ascii?: string;
    is_dangerous?: boolean;
  };
  has_overlay?: boolean;
  overlay_size?: number;
  overlay_entropy?: number;
}

export interface JarTriageInfo {
  is_jar: boolean;
  main_class?: string | null;
  permissions?: string | null;
  manifest_content?: string;
  class_count: number;
  embedded_binaries?: string[];
  packages?: string[];
  total_entries?: number;
  suspicious_apis?: Array<{ class_file: string; api: string; description: string }>;
}


export interface DomainIntelligence {
  target: string;
  is_ip: boolean;
  punycode_analysis?: {
    has_punycode?: boolean;
    is_punycode?: boolean;
    is_homograph: boolean;
    original?: string;
    punycode?: string;
    unicode_rendered: string;
    visual_appearance?: string;
    simulated_latin?: string;
    spoofed_chars?: Array<{
      char: string;
      codepoint: string;
      name: string;
      latin_lookalike: string;
    }>;
    homograph_confusables?: Array<{
      char: string;
      lookalike_latin: string;
      name: string;
      code_point: string;
      script: string;
    }>;
    lookalike_target?: string;
    display_warning?: string | null;
  };
  obfuscation_analysis?: {
    is_obfuscated: boolean;
    techniques: Array<{
      name: string;
      description: string;
      decoded_representation: string;
    }>;
  };
  dns_records?: {
    a?: string[];
    aaaa?: string[];
    mx?: Array<{ host: string; priority: number } | string>;
    ns?: string[];
    txt?: string[];
    soa?: string[];
    ptr?: string[];
  };
  whois?: {
    target?: string;
    registrar?: string;
    registration_date?: string;
    creation_date?: string;
    expiration_date?: string;
    last_updated?: string;
    domain_age_days?: number;
    domain_age_formatted?: string;
    registrant_org?: string;
    registrant_country?: string;
    nameservers?: string[];
    dnssec?: boolean;
    status?: string[];
    rdap_url?: string;
  };
  network?: {
    ip: string;
    reverse_dns?: string;
    asn?: string;
    as_org?: string;
    country?: string;
    city?: string;
  };
  co_hosted_domains?: string[];
  owner_intelligence?: {
    owner_name?: string;
    organization?: string;
    registrar?: string;
    network_name?: string;
    asn?: string;
    asn_org?: string;
    isp?: string;
    ip_range?: string;
    cidrs?: string[];
    more_domains?: string[];
    more_ip_ranges?: string[];
  };
  related_domains?: Array<{
    domain: string;
    relationships: string[];
    relationship_labels: string[];
    primary_relationship: string;
    evidence: string[];
    ips: string[];
    hosts_seen: string[];
    sources: string[];
    confidence: 'high' | 'medium' | 'low';
    observations: number;
    is_direct?: boolean;
    connection_type?: 'direct' | 'shared_infrastructure';
  }>;
  direct_affiliates?: Array<{
    domain: string;
    relationships: string[];
    relationship_labels: string[];
    primary_relationship: string;
    evidence: string[];
    ips: string[];
    hosts_seen: string[];
    sources: string[];
    confidence: 'high' | 'medium' | 'low';
    observations: number;
    is_direct?: boolean;
    connection_type?: 'direct' | 'shared_infrastructure';
  }>;
  shared_infrastructure_neighbors?: Array<{
    domain: string;
    relationships: string[];
    relationship_labels: string[];
    primary_relationship: string;
    evidence: string[];
    ips: string[];
    hosts_seen: string[];
    sources: string[];
    confidence: 'high' | 'medium' | 'low';
    observations: number;
    is_direct?: boolean;
    connection_type?: 'direct' | 'shared_infrastructure';
  }>;
  ownership_pivots?: {
    performed?: boolean;
    asn?: string | null;
    asn_holder?: string | null;
    network_name?: string | null;
    owner_org?: string | null;
    is_shared_infrastructure?: boolean;
    shared_reason?: string | null;
    asn_prefix_count?: number;
    asn_prefixes?: string[];
    spf_ip_ranges?: string[];
    ips_examined?: string[];
    ptr_probes?: number;
    elapsed_s?: number;
    direct_count?: number;
    shared_infrastructure_count?: number;
    pivots?: Array<{ name: string; status: string; found: number; detail?: string }>;
  };

  indicator_type?: string;
  normalized_value?: string;
  advanced_dns?: {
    target?: string;
    is_ip?: boolean;
    records?: {
      a?: string[];
      aaaa?: string[];
      cname?: string[];
      mx?: Array<{ host: string; priority: number } | string>;
      ns?: string[];
      soa?: Array<{ mname: string; rname: string; serial: number; refresh: number; retry: number; expire: number; minimum: number }>;
      txt?: string[];
      caa?: Array<{ flags: number; tag: string; value: string }>;
      srv?: string[];
      https?: string[];
      ptr?: string[];
    };
    ttls?: Record<string, number>;
    dnssec?: {
      enabled: boolean;
      validated: boolean;
      ds_records?: Array<{ key_tag: number; algorithm: number; digest_type: number; digest: string }>;
      dnskey_count?: number;
      notes?: string;
    };
    heuristics?: {
      has_wildcard_dns?: boolean;
      wildcard_ip?: string | null;
      low_ttl_detected?: boolean;
      min_ttl?: number | null;
      fast_flux_suspect?: boolean;
      suspicious_spf?: boolean;
      spf_details?: string | null;
      dangling_cnames?: Array<{
        domain: string;
        cname_target: string;
        provider: string;
        status: string;
        severity: string;
        vulnerability: string;
        description: string;
      }>;
    };
    anomalies?: Array<{
      type: string;
      severity: string;
      title: string;
      description: string;
    }>;
  };

  asn_profile?: {
    ip?: string;
    asn?: string;
    as_org?: string;
    isp?: string;
    country?: string;
    city?: string;
    classification?: string;
    is_cloud_provider?: boolean;
    is_bulletproof_suspect?: boolean;
    is_vpn_proxy?: boolean;
    risk_level?: string;
    reverse_ptr?: string | null;
    announced_cidrs?: string[];
  };

  tls_profile?: {
    target?: string;
    port?: number;
    has_tls?: boolean;
    live_cert?: {
      tls_version?: string;
      cipher_suite?: string;
      cipher_bits?: number;
      subject?: { common_name?: string; organization?: string; country?: string };
      issuer?: { common_name?: string; organization?: string; country?: string };
      sans?: string[];
      sha256_fingerprint?: string;
      sha1_fingerprint?: string;
      serial_number?: string;
      not_before?: string;
      not_after?: string;
      days_remaining?: number;
      is_expired?: boolean;
      is_self_signed?: boolean;
    };
    ct_logs?: {
      queried?: boolean;
      total_certificates_found?: number;
      discovered_subdomains?: string[];
      issuers?: string[];
      recent_entries?: Array<{ id?: number; common_name?: string; logged_at?: string; not_before?: string; not_after?: string }>;
    };
    security_findings?: Array<{ severity: string; title: string; description: string }>;
  };

  web_fingerprint?: {
    initial_url?: string;
    final_url?: string;
    status_code?: number | string | null;
    redirect_chain?: Array<{ hop: number; url: string; status_code: number | string; location?: string }>;
    hop_count?: number;
    response_headers?: Record<string, string>;
    server_technology?: string | null;
    powered_by?: string | null;
    security_headers?: {
      grade: string;
      score: number;
      hsts?: { present: boolean; value?: string | null };
      csp?: { present: boolean; value?: string | null };
      x_frame_options?: { present: boolean; value?: string | null };
      x_content_type_options?: { present: boolean; value?: string | null };
      referrer_policy?: { present: boolean; value?: string | null };
      permissions_policy?: { present: boolean; value?: string | null };
      recommendations?: string[];
    };
    favicon?: {
      found: boolean;
      url?: string | null;
      murmur_hash?: number | null;
      md5?: string | null;
      shodan_query?: string | null;
    };
    dom_analysis?: {
      title?: string | null;
      has_login_form?: boolean;
      login_form_actions?: string[];
      external_scripts?: string[];
      external_iframes?: string[];
      analytics_ids?: string[];
    };
    findings?: Array<{ severity: string; title: string; description: string }>;
  };

  threat_intelligence?: {
    indicator?: string;
    indicator_type?: string;
    overall_verdict: string;
    malicious_votes?: number;
    total_feeds_queried?: number;
    threat_tags?: string[];
    malware_families?: string[];
    feeds?: {
      virustotal?: { queried: boolean; verdict: string; detections: number; total: number; tags?: string[] };
      urlhaus?: { queried: boolean; verdict: string; url_count: number; tags?: string[] };
      threatfox?: { queried: boolean; verdict: string; ioc_count: number; tags?: string[] };
      abuseipdb?: { queried: boolean; verdict: string; abuse_confidence_score: number; total_reports: number };
      alienvault_otx?: { queried: boolean; verdict: string; pulse_count: number };
    };
  };

  attack_surface?: {
    root_domain?: string;
    total_discovered?: number;
    active_count?: number;
    dormant_count?: number;
    explanation?: string;
    subdomains?: Array<{
      subdomain: string;
      status: 'active' | 'unresolving' | string;
      status_label?: string;
      unresolving_reason?: string | null;
      ips: string[];
      is_root: boolean;
      discovered_from?: string;
      sources?: string[];
    }>;
  };

  active_recon?: {
    target?: string;
    authorized: boolean;
    executed: boolean;
    scanner?: string;
    scan_command?: string;
    open_ports_count?: number;
    raw_nmap?: string;
    services?: Array<{
      port: number;
      protocol: string;
      service: string;
      state: string;
      reason?: string | null;
      product?: string | null;
      version?: string | null;
      extrainfo?: string | null;
      tunnel?: string | null;
      cpe?: string[];
      banner?: string | null;
    }>;
    message?: string;
  };

  email_security?: {
    domain: string;
    dmarc: {
      present: boolean;
      raw_record?: string | null;
      policy: string;
      subdomain_policy?: string | null;
      percentage: number;
      aggregate_reports: string[];
      forensic_reports: string[];
      adkim: string;
      aspf: string;
      is_enforced: boolean;
    };
    dkim: {
      selectors_checked: number;
      selectors_found: Array<{
        selector: string;
        record: string;
        key_size_bits?: number | null;
      }>;
    };
    bimi: {
      present: boolean;
      raw_record?: string | null;
      svg_logo_url?: string | null;
      vmc_cert_url?: string | null;
      has_vmc: boolean;
    };
    spoofability: {
      status: 'VULNERABLE' | 'PARTIALLY_PROTECTED' | 'SECURED';
      risk_score: number;
      summary: string;
      remediations: string[];
    };
  };

  web_archive?: {
    target: string;
    archived: boolean;
    snapshot_count: number;
    first_seen?: string | null;
    last_seen?: string | null;
    age_days?: number | null;
    dormant_revival_detected: boolean;
    revival_gap_days?: number | null;
    status_code_distribution: Record<string, number>;
    wayback_calendar_url?: string;
    wayback_https_calendar_url?: string;
    wayback_www_calendar_url?: string;
    api_status?: 'available' | 'service_unavailable' | 'verified_not_archived' | 'pending' | string;
    api_status_code?: number | null;
    api_error_detail?: string | null;
    recent_snapshots: Array<{
      timestamp: string;
      date: string;
      status_code: string;
      mimetype?: string;
      archive_url: string;
    }>;
  };

  bgp_routing?: {
    ip: string;
    asn?: string | null;
    prefix?: string | null;
    rpki_status: string;
    is_rpki_valid?: boolean | null;
    is_anycast: boolean;
    anycast_provider?: string | null;
    bgp_visibility: {
      first_seen?: string | null;
      last_seen?: string | null;
      visibility_ratio?: number | null;
      peers_seeing?: number;
    };
  };

  passive_dns?: {
    target: string;
    is_ip: boolean;
    total_records: number;
    records: Array<{
      hostname: string;
      address: string;
      record_type: string;
      first_seen?: string | null;
      last_seen?: string | null;
      source: string;
    }>;
    discovered_domains: string[];
    discovered_ips: string[];
    sources: string[];
  };

  leak_search?: {
    target: string;
    leak_count: number;
    has_leaks: boolean;
    severity: string;
    leaks: Array<{
      id: string;
      source: string;
      date?: string | null;
      url?: string | null;
      tags: string[];
    }>;
  };

  active_security_probes?: {
    target: string;
    authorized: boolean;
    executed: boolean;
    message?: string;
    sensitive_files: {
      tested: number;
      exposed: Array<{
        path: string;
        title: string;
        category: string;
        risk: string;
        status_code: number;
        content_preview?: string;
      }>;
    };
    waf_detection: {
      detected: boolean;
      waf_name?: string | null;
      blocked_test?: boolean;
    };
    cors_and_methods: {
      tested: boolean;
      methods_allowed?: string[];
      dangerous_methods?: string[];
      cors_misconfigured: boolean;
      cors_origin_header?: string | null;
      cors_credentials_header?: string | null;
      cors_details?: string | null;
    };
    tls_cryptography: {
      tested: boolean;
      protocols?: Record<string, boolean>;
      deprecated_protocols_found?: string[];
      weak_ciphers?: string[];
    };
    api_endpoints: {
      tested: number;
      discovered: Array<{
        path: string;
        type: string;
        status_code: number;
        content_type?: string;
      }>;
    };
    smtp_relay_starttls: {
      tested: boolean;
      mx_host?: string | null;
      mx_ip?: string | null;
      banner?: string | null;
      starttls_supported?: boolean;
      open_relay?: boolean;
      details?: string | null;
    };
  };

  risk_scores?: {
    maliciousness?: { score: number; level: string; factors: Array<{ weight: number; title: string; description: string }> };
    infrastructure_risk?: { score: number; level: string; factors: Array<{ weight: number; title: string; description: string }> };
    exposure?: { score: number; level: string; factors: Array<{ weight: number; title: string; description: string }> };
    attribution_confidence?: { score: number; level: string; factors: Array<{ weight: number; title: string; description: string }> };
  };

  risk_flags?: Array<{
    severity: string;
    title: string;
    description: string;
  }>;

  fcrdns?: {
    ip: string;
    has_ptr: boolean;
    ptr_hosts: string[];
    primary_ptr?: string | null;
    forward_ips: string[];
    is_fcrdns_valid: boolean;
    status: 'VALID' | 'MISMATCH' | 'NO_PTR' | 'NO_IP' | string;
    details: string;
  };

  web_exposure?: {
    tested: boolean;
    target: string;
    has_exposure_data: boolean;
    robots_txt: {
      present: boolean;
      url?: string | null;
      status_code?: number | null;
      disallowed_count: number;
      allowed_count: number;
      sitemaps_declared: string[];
      user_agents: string[];
      disallow_paths: string[];
      sensitive_paths_flagged: Array<{ path: string; category: string; risk: string }>;
    };
    sitemap_xml: {
      present: boolean;
      url?: string | null;
      status_code?: number | null;
      total_urls_found: number;
      sample_urls: string[];
      sensitive_routes_flagged: Array<{ url: string; category: string; risk: string }>;
    };
    well_known: {
      security_txt?: { present: boolean; url?: string | null; fields: Record<string, string>; contacts: string[] };
      openid_configuration?: { present: boolean; url?: string | null; issuer?: string | null; endpoints: Record<string, string> };
      assetlinks_json?: { present: boolean; url?: string | null; package_names: string[] };
      apple_app_site_association?: { present: boolean; url?: string | null; app_ids: string[] };
    };
    risk_flags: Array<{ severity: string; title: string; description: string }>;
    positive_security_findings: Array<{ title: string; description: string }>;
  };

  vulnerability_intel?: {
    tested: boolean;
    total_vulnerabilities: number;
    cisa_kev_count: number;
    max_epss_score: number;
    has_critical_kev: boolean;
    findings: Array<{
      cve: string;
      title: string;
      product: string;
      detected_version: string;
      severity: string;
      cvss: number;
      epss: number;
      epss_percentile: string;
      cisa_kev: boolean;
      cisa_due_date?: string | null;
      confidence: 'CONFIRMED_VULNERABLE' | 'POTENTIALLY_VULNERABLE' | string;
      source: string;
      remediation: string;
      description: string;
      disclaimer: string;
    }>;
  };

  reverse_infrastructure?: {
    tested: boolean;
    target: string;
    reverse_ns: Array<{
      nameserver: string;
      is_shared_provider: boolean;
      associated_domains: string[];
      count: number;
      attribution_confidence: string;
    }>;
    reverse_mx: Array<{
      mx_host: string;
      is_shared_provider: boolean;
      associated_domains: string[];
      count: number;
      attribution_confidence: string;
    }>;
    discovered_siblings: string[];
    total_siblings_discovered: number;
  };

  typosquatting?: {
    tested: boolean;
    target: string;
    total_generated: number;
    active_registered_count: number;
    has_live_impersonators: boolean;
    lookalikes: Array<{
      domain: string;
      punycode?: string | null;
      technique: string;
      resolves: boolean;
      ips: string[];
      is_active_threat: boolean;
    }>;
  };

  tracking_pivots?: {
    tested: boolean;
    target: string;
    total_identifiers: number;
    tracking_identifiers: Array<{
      identifier: string;
      type: string;
      associated_domains: string[];
      count: number;
      attribution_confidence: string;
      query_url: string;
    }>;
    related_domains_from_analytics: string[];
    has_shared_tracking: boolean;
  };

  snapshot_diff?: {
    has_historical_baseline: boolean;
    baseline_job_id?: string | null;
    baseline_timestamp?: string | null;
    message?: string;
    total_changes_detected?: number;
    timeline_events?: Array<{
      type: string;
      severity: string;
      title: string;
      description: string;
      timestamp?: string;
    }>;
    delta_summary?: {
      ip_changed: boolean;
      added_ips?: string[];
      removed_ips?: string[];
      ns_changed: boolean;
      added_ns?: string[];
      removed_ns?: string[];
      cert_changed: boolean;
      new_subdomains_count: number;
      new_subdomains?: string[];
    };
  };
}

export interface EnrichedIocItem {
  indicator: string;
  type: 'ip' | 'domain';
  is_ip: boolean;
  asn?: string | null;
  as_org?: string | null;
  country?: string | null;
  root_domain?: string | null;
  resolved_ips?: string[];
  primary_ip?: string | null;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown' | string;
  threat_tags?: string[];
  malicious_score?: number;
  fcrdns?: {
    ip?: string;
    has_ptr?: boolean;
    primary_ptr?: string | null;
    status: 'VALID' | 'MISMATCH' | 'NO_PTR' | 'NO_IP' | string;
    is_fcrdns_valid?: boolean;
  };
  details?: Record<string, any>;
}

export interface EnrichIocsResponse {
  job_id: string;
  total_indicators: number;
  enriched: EnrichedIocItem[];
}

export interface ExtensionTriageInfo {
  is_extension: boolean;
  filename: string;
  crx_version?: number;
  manifest_version?: number;
  name: string;
  version: string;
  description: string;
  author: string;
  homepage_url: string;
  update_url: string;
  risk_score: number;
  risk_level: string;
  permissions: {
    critical: Array<{ permission: string; description: string }>;
    high: Array<{ permission: string; description: string }>;
    medium: Array<{ permission: string; description: string }>;
    low: Array<{ permission: string; description: string }>;
    host_permissions: string[];
  };
  background: {
    has_background: boolean;
    is_persistent: boolean;
    service_worker?: string | null;
    scripts: string[];
  };
  content_scripts: Array<{
    matches: string[];
    js: string[];
    run_at: string;
  }>;
  csp: {
    raw: string;
    allows_unsafe_eval: boolean;
    allows_unsafe_inline: boolean;
    allows_remote_scripts: boolean;
  };
  js_findings: Array<{
    file: string;
    title: string;
    severity: string;
    mitre: string;
    occurrences: number;
    snippet: string;
  }>;
  store_intelligence?: {
    extension_id?: string;
    store_name?: string;
    users_count?: string;
    downloads_count?: number | null;
    rating?: number;
    reviews_count?: string;
    developer_owner?: string;
    last_update_date?: string;
    store_version?: string;
    featured_badge?: boolean;
    google_esb_allowlist?: boolean;
    store_url?: string;
    reputation_score?: number;
    reputation_verdict?: string;
    reputation_summary?: string;
    is_active_in_store?: boolean;
  };
  is_webstore_signed?: boolean;
  package_signatures_count?: number;
  verified_item_id?: string | null;
  verified_item_version?: string | null;
  copyright_notice?: string | null;
  risk_flags: Array<{
    severity: string;
    title: string;
    description: string;
  }>;
  summary: string;
}

export interface AIImageProvenance {
  is_ai_generated: boolean;
  confidence: 'CLEAN' | 'SUSPICIOUS' | 'LIKELY_AI' | 'CONFIRMED_AI' | string;
  generator_tool?: string | null;
  explanation?: string;
  c2pa?: {
    detected: boolean;
    claim_generator?: string | null;
    digital_source_type?: string | null;
    is_algorithmic_media: boolean;
    actions: string[];
  };
  prompt_metadata?: {
    detected: boolean;
    tool?: string | null;
    prompt?: string | null;
    negative_prompt?: string | null;
    parameters?: Record<string, string>;
  };
  camera_metadata?: {
    has_camera_hardware_exif: boolean;
    make?: string | null;
    model?: string | null;
    lens?: string | null;
    iso?: string | null;
    exposure?: string | null;
  };
  ela_metrics?: {
    performed: boolean;
    mean_error: number;
    max_error: number;
    noise_uniformity: string;
  };
  indicators: string[];
}

export interface AppleScriptTriageInfo {
  is_applescript: boolean;
  filename: string;
  format: string;
  decompiled?: boolean;
  decompilation_method?: string;
  extracted_text_preview?: string;
  script_source?: string;
  line_count?: number;
  statement_count?: number;
  risk_score: number;
  risk_level: string;
  findings: Array<{
    title: string;
    severity: string;
    mitre: string;
    category?: string;
    description: string;
    snippet: string;
    count: number;
  }>;
  mitre_attack: Array<{
    technique_id: string;
    name: string;
  }>;
  capabilities?: {
    privilege_escalation?: Array<{ title: string; snippet: string; severity: string }>;
    credential_harvesting?: Array<{ title: string; snippet: string; severity: string }>;
    synthetic_input?: Array<{ title: string; snippet: string; severity: string }>;
    network_dropper?: Array<{ title: string; snippet: string; severity: string }>;
    persistence?: Array<{ title: string; snippet: string; severity: string }>;
    defense_evasion?: Array<{ title: string; snippet: string; severity: string }>;
    terminal_automation?: Array<{ title: string; snippet: string; severity: string }>;
    reverse_shell?: Array<{ title: string; snippet: string; severity: string }>;
  };
  targeted_applications?: Array<{
    name: string;
    reason: string;
    risk: string;
    tcc_permission: string;
    description: string;
    occurrences: number;
  }>;
  embedded_shell_commands?: Array<{
    command: string;
    context: string;
    is_dangerous: boolean;
    indicators: string[];
  }>;
  phishing_dialogs?: Array<{
    prompt: string;
    has_hidden_answer: boolean;
    has_default_answer: boolean;
    icon: string;
    buttons: string[];
    is_phishing: boolean;
  }>;
  iocs: {
    urls: string[];
    ips?: string[];
    commands: string[];
    file_paths?: string[];
  };
  summary: string;
}

export interface DeobfuscationResult {
  has_deobfuscated_content: boolean;
  base64_blocks?: Array<{
    encoded: string;
    decoded: string;
    encoding: string;
    bytes_len: number;
    extracted_urls?: string[];
    extracted_ips?: string[];
  }>;
  xor_candidates?: Array<{
    key_hex: string;
    key_decimal: number;
    matched_anchors: string[];
    revealed_strings_sample: string;
    extracted_urls?: string[];
    extracted_ips?: string[];
  }>;
  hex_candidates?: Array<{
    raw_hex: string;
    decoded: string;
  }>;
  extracted_urls?: string[];
  extracted_ips?: string[];
  summary: string;
}

export interface EmbeddedFileItem {
  id: number;
  name: string;
  source_type: string;
  parent_format: string;
  origin_stream: string;
  size: number;
  size_formatted: string;
  mime_type: string;
  md5: string;
  sha256: string;
  is_dangerous: boolean;
  threat_reason: string;
  disk_filename: string;
}

export interface EntropyChunk {
  index: number;
  offset_start: number;
  offset_end: number;
  offset_hex: string;
  chunk_size: number;
  entropy: number;
  label: string;
  state: 'critical' | 'warning' | 'clean' | 'sparse' | string;
}

export interface EntropyProfile {
  overall_entropy: number;
  max_entropy?: number;
  min_entropy?: number;
  profile: EntropyChunk[];
  chi_square?: {
    chi_square?: number;
    expected_per_byte?: number;
    is_random_like?: boolean;
    interpretation?: string;
  };
  monte_carlo?: {
    pi_estimate?: number;
    error_percent?: number;
    is_random?: boolean;
  };
  null_byte_percentage?: number;
  printable_byte_percentage?: number;
  high_entropy_blocks_count?: number;
  has_embedded_high_entropy_payload?: boolean;
  verdict?: string;
}

export interface ForensicCausalityLink {
  id: string;
  source_id: string;
  target_id: string;
  label: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  description?: string;
}

export interface ForensicSwimlane {
  id: string;
  title: string;
  artifact_type: string;
  event_count: number;
}

export interface ForensicTimelineEvent {
  id?: string;
  timestamp: string;
  epoch: number;
  category: 'system' | 'document' | 'email' | 'archive' | 'media' | 'evtx' | 'network' | 'filesystem' | 'binary' | 'anomaly' | 'threat_intel' | 'history' | string;
  source: string;
  event_type: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'warning' | 'info' | string;
  is_anomaly: boolean;
  filename?: string;
  job_id?: string;
  artifact_type?: string;
  kill_chain_phase?: 'initial_access' | 'execution' | 'persistence' | 'privilege_escalation' | 'defense_evasion' | 'credential_access' | 'discovery' | 'lateral_movement' | 'command_and_control' | 'threat_intel' | string;
  swimlane_id?: string;
}

export interface ForensicTimelineData {
  job_id: string;
  total_events: number;
  anomalies_count: number;
  events: ForensicTimelineEvent[];
  timestomping_report?: {
    detected: boolean;
    anomalies_count: number;
    risk_rating: 'CRITICAL' | 'HIGH' | 'CLEAN' | string;
    anomalies: ForensicTimelineEvent[];
  };
  swimlanes?: ForensicSwimlane[];
  causality_links?: ForensicCausalityLink[];
}

export interface SimilarSampleMatch {
  job_id: string;
  filename: string;
  sha256: string;
  similarity: number;
  risk_level: string;
  verdict: string;
  uploaded_at?: string;
  ssdeep?: string;
}

export interface CdrDiffModification {
  element: string;
  action: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  description: string;
}

export interface CdrDiffFileStats {
  filename: string;
  size_bytes: number;
  entropy: number;
  metadata_fields: number;
  sha256: string;
}

export interface CdrDiffInfo {
  original_file: CdrDiffFileStats;
  sanitized_file: CdrDiffFileStats;
  metrics: {
    bytes_reduced: number;
    reduction_percentage: number;
    entropy_delta: number;
    threats_neutralized: number;
    structural_modifications_count: number;
  };
  structural_modifications: CdrDiffModification[];
  actions_taken: string[];
  removed_items: string[];
  warnings: string[];
}

export interface EntityGraphNode {
  id: string;
  label: string;
  full_label: string;
  type: 'file' | 'embedded_file' | 'url' | 'domain' | 'ip' | 'certificate' | 'technique' | 'similar_sample' | string;
  risk: 'critical' | 'high' | 'warning' | 'medium' | 'low' | 'clean' | 'info' | string;
  x?: number;
  y?: number;
  details?: Record<string, any>;
}

export interface EntityGraphEdge {
  source: string;
  target: string;
  label: string;
  type: string;
}

export interface EntityGraphData {
  nodes: EntityGraphNode[];
  edges: EntityGraphEdge[];
  stats: {
    total_nodes: number;
    total_edges: number;
    embedded_count: number;
    url_count: number;
    technique_count: number;
    similar_count: number;
    certificate_count: number;
    threat_intel_count: number;
    email_artifacts_count: number;
    forensic_count?: number;
    cross_log_pivots_count?: number;
  };
}

export interface ReanalysisIntelDiff {
  is_reanalysis: boolean;
  previous_scan_date?: string;
  previous_job_id?: string;
  has_new_intelligence: boolean;
  new_vt_detections?: number;
  prev_vt_ratio?: string;
  curr_vt_ratio?: string;
  new_crowdstrike_threat?: boolean;
  crowdstrike_verdict?: string;
  new_clamav_signature?: string;
  summary_labels: string[];
}

export interface RedisCacheStats {
  connected: boolean;
  hits: number;
  misses: number;
  hit_ratio: number;
  total_cached_items: number;
  namespaces: Record<string, number>;
  used_memory_human: string;
}

export interface CdrFormatPolicy {
  format_name: string;
  enabled: boolean;
  allowed_options: string[];
  allowed_output_formats: string[];
}

export type CdrPoliciesMap = Record<string, CdrFormatPolicy>;

export interface PcapSummary {
  packet_count: number;
  duration_seconds: number;
  start_time?: string | null;
  end_time?: string | null;
  total_bytes: number;
  data_rate_kbps: number;
  link_type: string;
  file_format: string;
}

export interface PcapEndpoint {
  ip: string;
  packets: number;
  bytes: number;
  sent: number;
  recv: number;
  country?: string;
  city?: string;
  asn?: string;
  is_private?: boolean;
  abuseipdb?: {
    configured: boolean;
    status: string;
    score: number;
    total_reports: number;
    country?: string;
    usage_type?: string;
    domain?: string;
    isp?: string;
  } | null;
  otx?: {
    configured: boolean;
    status: string;
    pulse_count: number;
    pulse_names?: string[];
    tags?: string[];
  } | null;
  peers?: Array<{
    ip: string;
    packets: number;
    bytes: number;
    protocols: string[];
    ports: number[];
  }>;
  flow_ids?: string[];
}

export interface PcapConversation {
  id: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  transport: string;
  protocol: string;
  packets: number;
  bytes: number;
  start_time: number;
  end_time: number;
  duration_seconds?: number;
  start_offset?: number;
  end_offset?: number;
  throughput_kbps?: number;
  client_packets?: number;
  client_bytes?: number;
  server_packets?: number;
  server_bytes?: number;
  state?: string;
  flags_summary?: {
    syn: number;
    ack: number;
    fin: number;
    rst: number;
    psh: number;
    urg: number;
  };
  payload_preview_hex?: string;
  payload_preview_ascii?: string;
  payload_size?: number;
}

export interface PcapDnsQuery {
  domain: string;
  query_type: string;
  resolved_ips: string[];
  client_ip: string;
  is_suspicious: boolean;
  threat_status?: string;
  high_entropy?: boolean;
  entropy_score?: number;
  is_tunneling_candidate?: boolean;
}

export interface PcapTlsSession {
  sni: string;
  client_ip: string;
  server_ip: string;
  server_port: number;
  tls_version: string;
  ja3?: string;
  ja3_raw?: string;
  ja3_match?: string | null;
  ja3s?: string;
  ja3s_raw?: string;
  ja3s_match?: string | null;
}

export interface PcapBeaconingFlow {
  src_ip: string;
  dst_ip: string;
  packet_count: number;
  mean_interval_sec: number;
  std_dev_sec: number;
  jitter_percent: number;
  min_interval: number;
  max_interval: number;
}

export interface PcapSshSession {
  timestamp?: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  hassh?: string;
  hassh_algorithms?: string;
}

export interface PcapHttpTransaction {
  type?: string;
  method?: string;
  uri?: string;
  host?: string;
  full_url?: string;
  user_agent?: string;
  src_ip: string;
  dst_ip: string;
  status_code?: string;
  server?: string;
  content_type?: string;
  credentials?: { username: string; password: string } | null;
  transferred_file?: {
    filename: string;
    protocol: string;
    source_url?: string;
    client_ip: string;
    server_ip: string;
    is_dangerous: boolean;
  } | null;
}

export interface PcapCredential {
  protocol: string;
  username: string;
  password: string;
  client_ip: string;
  server_ip: string;
}

export interface PcapTransferredFile {
  filename: string;
  protocol: string;
  command?: string;
  source_url?: string;
  client_ip: string;
  server_ip: string;
  is_dangerous: boolean;
}

export interface PcapCarvedFile {
  id: number;
  name: string;
  filename: string;
  disk_filename?: string;
  size: number;
  size_formatted?: string;
  md5: string;
  sha256: string;
  mime_type: string;
  source_type?: string;
  source_protocol?: string;
  source_stream?: string;
  source_url?: string;
  is_dangerous?: boolean;
  threat_reason?: string;
  threat_intel?: {
    virustotal?: any;
    threatfox?: any;
    malwarebazaar?: any;
    circl?: any;
    malicious?: boolean;
  };
  preview_type?: 'text' | 'image' | 'hex';
  preview_text?: string;
  preview_base64?: string;
}

export interface PcapSoftwareIdentified {
  name: string;
  category: string;
  role: string;
  ip: string;
  source_protocol: string;
  raw_banner: string;
  risk_hint?: string;
}

export interface PcapGanttItem {
  flow_id: string;
  protocol: string;
  src_endpoint: string;
  dst_endpoint: string;
  start_seconds: number;
  duration_seconds: number;
  bytes: number;
  packets: number;
  start_pct: number;
  width_pct: number;
  summary_narrative?: string;
  site?: string;
  method?: string;
  path?: string;
  query_params?: string;
  status_code?: number;
  user_agent?: string;
  commands?: string[];
  transferred_file?: {
    filename: string;
    filesize: number;
    filesize_formatted?: string;
    sha256?: string;
    md5?: string;
    direction?: 'upload' | 'download';
  };
  dns_query?: string;
  dns_answers?: string[];
  smb_share?: string;
  smb_action?: string;
  sql_query?: string;
  email_subject?: string;
  email_sender?: string;
  email_recipient?: string;
  tls_sni?: string;
  ja3?: string;
}

export interface PcapSearchQuery {
  engine: string;
  search_engine?: string;
  query: string;
  client_ip: string;
  server_ip: string;
  timestamp: string | number;
  time_iso?: string;
  url: string;
}

export interface PcapWebSession {
  timestamp: string;
  client_ip: string;
  server_ip: string;
  host: string;
  uri: string;
  method: string;
  content_type: string;
  submitted_fields: Record<string, string>;
  raw_payload_preview: string;
  is_credential_submission: boolean;
  is_sensitive: boolean;
}

export interface PcapExfiltrationFileRecord {
  direction: 'uploaded' | 'downloaded';
  filename: string;
  size: number;
  sha256?: string;
  md5?: string;
  mime_type?: string;
  timestamp: string;
  client_ip: string;
  server_ip: string;
  protocol: string;
  carved_id?: string;
}

export interface PcapExfiltrationTracker {
  total_uploaded_bytes: number;
  total_downloaded_bytes: number;
  upload_to_download_ratio: number;
  exfiltration_risk_level: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'NORMAL';
  risk_reason: string;
  file_movement_ledger: PcapExfiltrationFileRecord[];
}

export interface PcapTerminalDialogue {
  direction: 'client' | 'server';
  text: string;
  timestamp?: string;
}

export interface PcapTerminalSession {
  session_id: string;
  protocol: 'Telnet' | 'FTP' | 'Raw TCP Shell' | 'Redis' | 'MySQL' | string;
  client: string;
  server: string;
  start_time: string;
  end_time: string;
  total_commands: number;
  executed_commands: string[];
  dialogue: PcapTerminalDialogue[];
  file_operations?: Array<{
    command: string;
    filename: string;
    direction: 'STOR' | 'RETR' | 'READ' | 'WRITE' | string;
  }>;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  risk_indicators: string[];
}

export interface PcapEmailAttachment {
  filename: string;
  size: number;
  content_type: string;
  is_executable_or_script: boolean;
  sha256?: string;
}

export interface PcapEmail {
  email_id: string;
  protocol: 'SMTP' | 'POP3' | 'IMAP' | string;
  client: string;
  server: string;
  timestamp: string;
  from: string;
  to: string[];
  subject: string;
  body_text: string;
  body_html?: string;
  attachments: PcapEmailAttachment[];
  phishing_indicators: string[];
  is_suspicious: boolean;
}

export interface PcapInfo {
  summary: PcapSummary;
  protocols: Record<string, number>;
  top_endpoints: PcapEndpoint[];
  conversations: PcapConversation[];
  dns_queries: PcapDnsQuery[];
  tls_sessions: PcapTlsSession[];
  http_transactions: PcapHttpTransaction[];
  credentials: PcapCredential[];
  transferred_files: PcapTransferredFile[];
  carved_files?: PcapCarvedFile[];
  software_identified?: PcapSoftwareIdentified[];
  gantt_items?: PcapGanttItem[];
  beaconing_flows?: PcapBeaconingFlow[];
  ssh_sessions?: PcapSshSession[];
  urls: string[];
  search_queries?: PcapSearchQuery[];
  web_sessions?: PcapWebSession[];
  exfiltration_tracker?: PcapExfiltrationTracker;
  terminal_sessions?: PcapTerminalSession[];
  emails?: PcapEmail[];
}

// -------------------------------------------------------------
// Forensic Windows Shell Link (.LNK) Types
// -------------------------------------------------------------
export interface LnkHeader {
  header_size: number;
  clsid_matches: boolean;
  link_flags: string;
  file_attributes: string;
  show_command: number;
  show_command_desc: string;
  target_file_size: number;
  icon_index: number;
}

export interface LnkTimestamps {
  creation_time?: string | null;
  access_time?: string | null;
  write_time?: string | null;
}

export interface LnkTargetsAndPaths {
  target_command?: string;
  description?: string;
  relative_path?: string;
  working_directory?: string;
  arguments?: string;
  icon_location?: string;
  link_info?: Record<string, any>;
  id_list_items?: string[];
}

export interface LnkOverlay {
  size: number;
  is_executable: boolean;
  is_zip: boolean;
  is_powershell: boolean;
  sha256?: string;
  preview?: string;
}

export interface LnkInfo {
  header: LnkHeader;
  timestamps: LnkTimestamps;
  targets_and_paths: LnkTargetsAndPaths;
  deobfuscated_payload?: string | null;
  lolbins?: Array<{ binary: string; role: string }>;
  icon_spoofed?: boolean;
  icon_spoof_details?: string | null;
  overlay?: LnkOverlay | null;
  extra_blocks?: Array<{ signature: string; name: string; size: number }>;
  urls?: string[];
}

// -------------------------------------------------------------
// Automated Detection Rules (Microsoft Sentinel KQL & YARA)
// -------------------------------------------------------------
export interface DetectionRules {
  yara_rule: string;
  sentinel_kql: {
    mde_process_creation: string;
    windows_event_4688: string;
    mde_file_events: string;
    mde_network_c2: string;
    email_gateway: string;
    sentinel_analytics_rule: string;
  };
  indicators_used: {
    sha256?: string;
    md5?: string;
    imphash?: string;
    rich_header_hash?: string;
    domains: string[];
    ips: string[];
    urls: string[];
    mitre_techniques: string[];
  };
  generated_at: string;
}

// -------------------------------------------------------------
// Multi-File Incident Investigation Workspace & BinDiff
// -------------------------------------------------------------
export interface WorkspaceJob {
  jobId: string;
  filename: string;
  category?: string;
  riskLevel?: string;
  riskScore?: number;
  fileSize?: number;
}

export interface IncidentFileSummary {
  job_id: string;
  filename: string;
  original_filename: string;
  category: string;
  mime_type: string;
  file_size: number;
  risk_level: string;
  risk_score: number;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
    ssdeep?: string;
    tlsh?: string;
    imphash?: string;
    rich_header_hash?: string;
  };
  compile_time?: string;
  created_at?: string;
}

export interface IncidentCampaignSummary {
  overall_risk_level: string;
  overall_risk_score: number;
  total_files: number;
  shared_ioc_count: number;
  total_unique_ips: number;
  total_unique_domains: number;
  total_mitre_techniques: number;
  attack_stages_detected: string[];
  executive_narrative: string;
  key_correlations: string[];
}

export interface BinaryDiffSection {
  name: string;
  status: 'MATCHED' | 'MODIFIED' | 'SAMPLE_A_ONLY' | 'SAMPLE_B_ONLY';
  va_a: string;
  va_b: string;
  vsize_a: number;
  vsize_b: number;
  vsize_delta: number;
  rsize_a: number;
  rsize_b: number;
  rsize_delta: number;
  entropy_a: number;
  entropy_b: number;
  entropy_delta: number;
  is_packed_a?: boolean;
  is_packed_b?: boolean;
}

export interface BinaryDiffImport {
  name?: string;
  api?: string;
  dll: string;
  is_suspicious?: boolean;
  severity?: string;
  description?: string;
  risk_reason?: string;
}

export interface BinaryDiffTool {
  tool_id: number;
  tool_name: string;
  build_a: any;
  build_b: any;
  count_a: number;
  count_b: number;
  status: string;
}

export interface BinaryDiffInstruction {
  status: 'MATCHED' | 'OPERAND_DIFF' | 'OPCODE_DIFF' | 'SAMPLE_A_ONLY' | 'SAMPLE_B_ONLY';
  inst_a?: { address: string; mnemonic: string; op_str: string; bytes: string } | null;
  inst_b?: { address: string; mnemonic: string; op_str: string; bytes: string } | null;
}

export interface BasicBlockInstruction {
  address: string;
  mnemonic: string;
  op_str: string;
  bytes?: string;
  diff_status?: 'MATCHED' | 'OPERAND_DIFF' | 'OPCODE_DIFF' | 'SAMPLE_A_ONLY' | 'SAMPLE_B_ONLY';
}

export interface BasicBlock {
  id: string;
  label: string;
  start_addr: string;
  end_addr: string;
  index: number;
  instruction_count: number;
  instructions: BasicBlockInstruction[];
  match_status: 'MATCHED' | 'CHANGED' | 'UNIQUE_A' | 'UNIQUE_B';
  similarity: number;
  matched_block_id?: string | null;
  has_loop_exit?: boolean;
  is_conditional?: boolean;
  is_loop_target?: boolean;
}

export interface CFGEdge {
  source: string;
  target: string;
  type: 'true' | 'false' | 'unconditional' | 'fallthrough' | 'loop';
  label: string;
  is_loop?: boolean;
}

export interface FlowGraphDiff {
  available: boolean;
  cfg_similarity: number;
  matched_blocks_count: number;
  changed_blocks_count: number;
  unique_a_blocks_count: number;
  unique_b_blocks_count: number;
  sample_a_cfg: {
    blocks: BasicBlock[];
    edges: CFGEdge[];
  };
  sample_b_cfg: {
    blocks: BasicBlock[];
    edges: CFGEdge[];
  };
}

export interface BinaryDiffPair {
  binary_a: {
    job_id: string;
    filename: string;
    sha256: string;
    imphash?: string;
    arch: string;
    compile_time?: string;
  };
  binary_b: {
    job_id: string;
    filename: string;
    sha256: string;
    imphash?: string;
    arch: string;
    compile_time?: string;
  };
  similarity_score: number;
  confidence: string;
  metrics: {
    section_similarity: number;
    import_similarity: number;
    disassembly_similarity: number;
    cfg_similarity?: number;
    rich_header_similarity: number;
    imphash_matched: boolean;
    rich_header_matched: boolean;
  };
  sections_diff: BinaryDiffSection[];
  imports_diff: {
    similarity_percent: number;
    matched_count: number;
    unique_a_count: number;
    unique_b_count: number;
    total_union_count: number;
    matched: BinaryDiffImport[];
    unique_a: BinaryDiffImport[];
    unique_b: BinaryDiffImport[];
  };
  rich_header_diff: {
    available: boolean;
    status: string;
    similarity_percent?: number;
    tools: BinaryDiffTool[];
  };
  disassembly_diff: {
    available: boolean;
    similarity_percent: number;
    total_rows: number;
    instructions: BinaryDiffInstruction[];
  };
  flow_graph_diff?: FlowGraphDiff;
}

export interface BinaryDiffData {
  available: boolean;
  message?: string;
  binary_count: number;
  total_pairs?: number;
  pairs?: BinaryDiffPair[];
  active_pair?: BinaryDiffPair;
}

export interface CampaignTimelineEvent {
  timestamp: string;
  iso_timestamp: string;
  job_id: string;
  filename: string;
  category: string;
  risk_level: string;
  source: string;
  event: string;
  description: string;
  computer?: string;
  user?: string;
  severity?: string;
  is_anomaly: boolean;
  is_timestomp?: boolean;
  staging_phase: string;
}

export interface CampaignTimelineData {
  total_events: number;
  anomalies_count: number;
  timestomp_detected: boolean;
  staging_sequence: Array<{
    phase: string;
    first_event: string;
    filename: string;
    timestamp: string;
  }>;
  events: CampaignTimelineEvent[];
}

export interface CampaignHashComparison {
  files: Array<{
    job_id: string;
    filename: string;
    category: string;
    file_size: number;
    md5: string;
    sha1: string;
    sha256: string;
    ssdeep?: string;
    tlsh?: string;
    imphash?: string;
    rich_header_hash?: string;
  }>;
  pairwise_matrix: Array<{
    file_a: string;
    job_id_a: string;
    file_b: string;
    job_id_b: string;
    exact_sha256_match: boolean;
    imphash_match: boolean;
    rich_header_match: boolean;
    fuzzy_ssdeep_score: number;
    overall_similarity_pct: number;
  }>;
  shared_components: Array<{
    hash: string;
    sightings: Array<{ job_id: string; filename: string; component_name: string }>;
    occurrences: number;
  }>;
}

export interface CampaignIocItem {
  ip?: string;
  domain?: string;
  url?: string;
  username?: string;
  country?: string;
  city?: string;
  asn?: string;
  is_private?: boolean;
  is_shared: boolean;
  seen_in_files: Array<{ job_id: string; filename: string }>;
  occurrences: number;
  sources?: string[];
}

export interface CampaignIocComparison {
  ips: CampaignIocItem[];
  domains: CampaignIocItem[];
  urls: CampaignIocItem[];
  usernames: CampaignIocItem[];
  shared_ip_count: number;
  shared_domain_count: number;
  shared_url_count: number;
  shared_user_count: number;
}

export interface CampaignMitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  seen_in_files: Array<{ job_id: string; filename: string }>;
  confidence: string;
  is_shared: boolean;
}

export interface CampaignMitreTactic {
  tactic: string;
  techniques: CampaignMitreTechnique[];
}

export interface CampaignMitreData {
  total_techniques: number;
  active_tactics_count: number;
  tactics: CampaignMitreTactic[];
}

export interface IncidentCorrelationData {
  success: boolean;
  error?: string;
  total_jobs: number;
  files: IncidentFileSummary[];
  campaign_summary: IncidentCampaignSummary;
  campaign_graph: {
    total_nodes: number;
    total_edges: number;
    shared_nodes_count: number;
    nodes: Array<{
      id: string;
      label: string;
      full_label: string;
      type: string;
      risk: string;
      tier: number;
      is_shared?: boolean;
      file_ids?: string[];
      details?: Record<string, any>;
    }>;
    edges: Array<{
      source: string;
      target: string;
      label: string;
      type: string;
      is_shared?: boolean;
    }>;
  };
  binary_diff: BinaryDiffData;
  timeline_comparison: CampaignTimelineData;
  hash_comparison: CampaignHashComparison;
  ioc_comparison: CampaignIocComparison;
  mitre_campaign: CampaignMitreData;
  evtx_fleet_forensics?: EVTXFleetForensics;
  pcap_fleet_intelligence?: PCAPFleetIntelligence;
  cross_file_references?: {
    total_references: number;
    references: CrossFileReference[];
    by_job: Record<string, { outgoing: CrossFileReference[]; incoming: CrossFileReference[] }>;
  };
}

export interface CrossFileReference {
  source_job_id: string;
  source_filename: string;
  target_job_id: string;
  target_filename: string;
  reference_type: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  label: string;
  detail: string;
  matched_by: 'filename' | 'hash' | 'uri' | 'code' | 'component';
  matched_value: string;
  event_id?: string;
  computer?: string;
}

export interface HostTelemetrySummary {
  job_id: string;
  filename: string;
  hostname: string;
  channel: string;
  total_events: number;
  threat_events_count: number;
  time_start?: string | null;
  time_end?: string | null;
  unique_users: string[];
  unique_ips: string[];
  top_event_ids: Record<string, number>;
  has_log_cleared: boolean;
}

export interface LateralMovementStage {
  step: number;
  title: string;
  description: string;
  event_id: number;
  timestamp: string;
}

export interface LateralMovementChain {
  chain_id: string;
  source_host: string;
  target_host: string;
  user_account: string;
  protocol: string;
  technique: string;
  mitre_id: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string;
  stages: LateralMovementStage[];
  evidence_event_ids: number[];
}

export interface PasswordSprayUserEntry {
  username: string;
  total_failures: number;
  hosts_targeted: string[];
  source_ips: string[];
  is_spray_target: boolean;
}

export interface PasswordSprayCampaign {
  pattern: string;
  type: string;
  failures: number;
  threat_level: string;
}

export interface AntiForensicsAlert {
  host: string;
  event_id: number;
  title: string;
  user: string;
  timestamp: string;
  severity: string;
  channel: string;
  mitre_id: string;
}

export interface FleetPrivilegeEvent {
  host: string;
  event_id: number;
  user: string;
  privileges: string;
  timestamp: string;
  severity: string;
}

export interface FleetLolbinDivergence {
  host: string;
  process_name: string;
  command_line: string;
  parent_process: string;
  user: string;
  timestamp: string;
  is_suspicious: boolean;
  mitre_id: string;
}

export interface EVTXFleetForensics {
  available: boolean;
  message?: string;
  total_hosts: number;
  total_logs: number;
  fleet_risk_level: string;
  fleet_risk_score: number;
  narrative: string;
  hosts: HostTelemetrySummary[];
  lateral_movement_chains: LateralMovementChain[];
  password_spray_analysis: {
    total_failed_logons: number;
    campaigns: PasswordSprayCampaign[];
    user_matrix: PasswordSprayUserEntry[];
  };
  anti_forensics_alerts: AntiForensicsAlert[];
  privilege_escalation_events: FleetPrivilegeEvent[];
  lolbin_divergence: FleetLolbinDivergence[];
  unified_evtx_info?: EvtxInfo;
  combined_anti_analysis?: AntiAnalysisInfo;
}

export interface PCAPFleetIntelligence {
  available: boolean;
  message?: string;
  total_captures: number;
  total_fleet_packets?: number;
  total_fleet_bytes?: number;
  fleet_risk_level?: string;
  fleet_risk_score?: number;
  narrative?: string;
  captures_summary?: Array<{
    job_id: string;
    filename: string;
    packet_count: number;
    duration_seconds: number;
    start_time?: string;
    end_time?: string;
    protocols: string[];
    conversations_count: number;
    unique_ips_count: number;
    unique_domains_count: number;
    credentials_count: number;
    carved_files_count: number;
    beaconing_count: number;
  }>;
  cross_capture_ips?: Array<{
    ip: string;
    seen_in_captures: string[];
    capture_count: number;
    is_private: boolean;
    country: string;
    city: string;
    asn: string;
    roles: string[];
  }>;
  cross_capture_domains?: Array<{
    domain: string;
    seen_in_captures: string[];
    capture_count: number;
  }>;
  shared_credentials?: Array<{
    username: string;
    protocols: string[];
    seen_in_captures: string[];
    is_cross_capture: boolean;
    passwords: string[];
    targets: string[];
  }>;
  all_beaconing?: Array<{
    dst_ip: string;
    dst_port: number;
    interval_seconds: number;
    jitter_percent: number;
    capture_file: string;
    job_id: string;
  }>;
  lateral_network_flows?: Array<{
    src_ip: string;
    dst_ip: string;
    port: number;
    service: string;
    packets: number;
    bytes: number;
    job_id: string;
    filename: string;
    timestamp?: string;
  }>;
  all_transferred_files?: Array<{
    filename: string;
    file_type?: string;
    sha256?: string;
    size_bytes?: number;
    capture_file: string;
    job_id: string;
  }>;
  unified_protocols?: Record<string, number>;
}

// -------------------------------------------------------------
// Android APK Mobile Security & Dalvik DEX Analysis
// -------------------------------------------------------------
export interface ApkPermission {
  permission: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  mitre?: string;
  mitre_name?: string;
}

export interface ApkComponent {
  name: string;
  exported: boolean;
  permission?: string;
  intent_filters?: string[];
  actions?: string[];
}

export interface ApkDetectedApi {
  pattern?: string;
  api: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  mitre?: string;
  mitre_name?: string;
  count: number;
  evidence: string[];
}

export interface ApkDexInfo {
  dex_count: number;
  classes_count: number;
  total_strings_count: number;
  detected_apis: ApkDetectedApi[];
  string_samples?: string[];
}

export interface ApkCertificate {
  subject?: string;
  issuer?: string;
  serial_number?: string;
  valid_from?: string;
  valid_until?: string;
  sha256_fingerprint?: string;
  is_debug_key?: boolean;
  is_self_signed?: boolean;
}

export interface ApkAnalysisData {
  is_apk: boolean;
  is_standalone_dex?: boolean;
  package_name?: string;
  version_code?: string;
  version_name?: string;
  min_sdk?: string | number;
  target_sdk?: string | number;
  compile_sdk?: string | number;
  app_name?: string;
  app_icon?: string;
  security_flags?: {
    debuggable?: boolean;
    allow_backup?: boolean;
    uses_cleartext_traffic?: boolean;
    network_security_config?: boolean;
    test_only?: boolean;
    [key: string]: any;
  };
  permissions?: string[];
  dangerous_permissions?: ApkPermission[];
  components?: {
    activities?: ApkComponent[];
    services?: ApkComponent[];
    receivers?: ApkComponent[];
    providers?: ApkComponent[];
  };
  exported_components?: {
    activities?: string[];
    services?: string[];
    receivers?: string[];
    providers?: string[];
  };
  signing_info?: {
    has_v1_signature?: boolean;
    has_v2_or_v3_signature?: boolean;
    is_debug_key?: boolean;
    is_self_signed?: boolean;
    subject?: string;
    issuer?: string;
    serial_number?: string;
    valid_from?: string;
    valid_until?: string;
    sha256_fingerprint?: string;
    certificates?: ApkCertificate[];
  };
  dex_info?: ApkDexInfo;
  native_architectures?: string[];
  native_libraries?: string[];
  embedded_assets?: string[];
  iocs?: {
    urls?: string[];
    ips?: string[];
  };
  mitre_mobile_techniques?: Array<{
    id: string;
    name: string;
  }>;
  risk_score?: number;
  risk_level?: string;
}

// -------------------------------------------------------------
// Java Bytecode & Source Forensic Analysis
// -------------------------------------------------------------
export interface JavaMethodCall {
  class_file?: string;
  api: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  mitre?: string;
  mitre_name?: string;
  line_number?: number;
}

export interface JavaAnalysisData {
  is_java: boolean;
  java_subtype?: 'source' | 'class' | 'jar';
  classes_count?: number;
  packages_count?: number;
  classes_list?: string[];
  main_class?: string;
  premain_class?: string;
  agent_class?: string;
  permissions?: string;
  code_preview?: string;
  class_info?: {
    major_version?: number;
    minor_version?: number;
    java_version?: string;
    constant_pool_count?: number;
    methods_count?: number;
    fields_count?: number;
    interfaces_count?: number;
  };
  dangerous_apis?: JavaMethodCall[];
  embedded_binaries?: string[];
  rat_detections?: string[];
  iocs?: {
    urls?: string[];
    ips?: string[];
  };
  mitre_techniques?: Array<{
    id: string;
    name: string;
  }>;
  risk_score?: number;
  risk_level?: string;
}








