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
  subdomains?: string[];
  subfinder_dnsx?: SubfinderDnsxResult;
}

export interface SubfinderDnsxSubdomain {
  subdomain: string;
  domain?: string;
  ips?: string[];
  status?: string;
}

export interface SubfinderDnsxResult {
  executed: boolean;
  available?: boolean;
  command?: string;
  target_domain?: string;
  total_discovered?: number;
  subdomains?: SubfinderDnsxSubdomain[];
  discovered_ips?: string[];
  error?: string | null;
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
  file_integrity?: EmailFileIntegrity;
  auth_posture?: EmailAuthPosture;
  lookalike_analysis?: EmailLookalikeAnalysis;
  url_threats?: EmailUrlThreats;
  html_forensics?: EmailHtmlForensics;
  attachment_forensics?: EmailAttachmentForensics;
  bec_analysis?: EmailBecAnalysis;
  email_verdict?: EmailVerdict;
  offline_tools_guide?: EmailOfflineToolsGuide;
}

export interface EmailVerdict {
  verdict: 'Malicious' | 'Suspicious' | 'Potentially Phishing / BEC' | 'No Known Threat Detected' | 'Inconclusive';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  confidence_score: number;
  threat_categories: string[];
  key_assessment_rationale: string[];
  mitre_attack_techniques: string[];
  containment_guidance: string[];
}

export interface EmailFileIntegrity {
  format: string;
  is_valid_format: boolean;
  file_size: number;
  file_hashes: {
    sha256: string;
    sha1: string;
    md5: string;
  };
  header_body_separated: boolean;
  duplicate_headers: Array<{
    name: string;
    count: number;
    values: string[];
  }>;
  mime_structure: {
    is_multipart: boolean;
    total_parts: number;
    max_nesting_depth: number;
    parser_defects: string[];
    parts: Array<{
      part_index: number;
      content_type: string;
      content_disposition: string;
      filename?: string | null;
      transfer_encoding: string;
      decoded_size: number;
      defects: string[];
    }>;
  };
  clock_skew: {
    drift_detected: boolean;
    date_header?: string | null;
    received_timestamp?: string | null;
    skew_hours?: number;
    details?: string;
  };
  unicode_anomalies: {
    bidi_controls_detected: boolean;
    zero_width_chars_detected: boolean;
    unicode_chars_found: string[];
    bidi_sample?: string;
    zero_width_sample?: string;
  };
}

export interface EmailAuthPosture {
  spf: {
    status: string;
    envelope_domain: string;
    client_ip: string;
    mechanism: string;
    aligned: boolean;
  };
  dkim: {
    status: string;
    signing_domain: string;
    selector: string;
    algorithm: string;
    aligned: boolean;
  };
  dmarc: {
    status: string;
    policy: string;
    spf_alignment: boolean;
    dkim_alignment: boolean;
    from_domain: string;
  };
  arc: {
    seal_status: string;
    chain_valid: boolean;
    has_arc: boolean;
  };
  auth_summary: string;
  flags: string[];
}

export interface EmailLookalikeAnalysis {
  display_name: string;
  from_address: string;
  from_domain: string;
  reply_to_address: string;
  reply_to_domain: string;
  return_path_domain: string;
  is_free_webmail: boolean;
  display_name_spoofing: {
    is_spoofed: boolean;
    impersonated_entity?: string | null;
    details?: string | null;
  };
  lookalike_domain: {
    is_lookalike: boolean;
    impersonated_brand?: string;
    canonical_domain?: string;
    edit_distance?: number | null;
    is_punycode: boolean;
  };
  vip_executive_impersonation: {
    is_impersonating: boolean;
    role?: string;
    details?: string | null;
  };
  reply_to_mismatch: {
    is_mismatched: boolean;
    is_free_webmail_redirect: boolean;
    details?: string | null;
  };
}

export interface EmailUrlThreats {
  total_urls_extracted: number;
  deceptive_links_count: number;
  ip_host_links_count: number;
  userinfo_obfuscated_count: number;
  shortened_links_count: number;
  credential_harvesting_count: number;
  url_items: Array<{
    url: string;
    host: string;
    is_deceptive: boolean;
    claimed_text?: string;
    is_ip_host: boolean;
    has_userinfo: boolean;
    is_shortener: boolean;
    is_credential_target: boolean;
  }>;
}

export interface EmailHtmlForensics {
  has_html: boolean;
  hidden_text_detected: boolean;
  hidden_text_items: Array<{
    text: string;
    reason: string;
  }>;
  credential_forms: Array<{
    action: string;
    method: string;
    inputs: string[];
    has_password_input: boolean;
  }>;
  meta_refreshes: Array<{
    content: string;
  }>;
  data_urls: Array<{
    mime_type: string;
    data_snippet: string;
  }>;
  iframes: Array<{
    src: string;
    width: string;
    height: string;
  }>;
  html_comments: string[];
}

export interface EmailAttachmentForensics {
  total_attachments: number;
  dangerous_count: number;
  mismatch_count: number;
  macro_enabled_count: number;
  double_extension_count: number;
  nested_messages_count: number;
  inspected_attachments: Array<{
    filename: string;
    size: number;
    declared_mime: string;
    detected_type: string;
    is_mismatch: boolean;
    is_dangerous: boolean;
    has_macros: boolean;
    has_double_extension: boolean;
    is_nested_email: boolean;
    sha256: string;
    threat_reason?: string;
  }>;
}

export interface EmailBecAnalysis {
  bec_detected: boolean;
  bec_risk_score: number;
  bank_payment_redirection: {
    detected: boolean;
    matches: string[];
  };
  urgency_secrecy: {
    detected: boolean;
    matches: string[];
  };
  gift_card_fraud: {
    detected: boolean;
    matches: string[];
  };
  executive_wire_fraud: {
    detected: boolean;
    matches: string[];
  };
  financial_fraud_types: string[];
  indicators: string[];
}

export interface EmailOfflineToolItem {
  tool: string;
  command: string;
  purpose: string;
}

export type EmailOfflineToolsGuide = Record<string, EmailOfflineToolItem>;

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
  pe_verdict?: PeSecurityVerdict;
  pe_capabilities?: PeCapabilityItem[];
  dll_forensics?: DllForensics;
  dotnet_assembly?: DotNetAssemblyForensics;
  pe_vulnerabilities?: PeVulnerabilityForensics;
  overlay_forensics?: PeOverlayForensics;
}

export interface PeCapabilityItem {
  id: string;
  name: string;
  tactic: string;
  mitre_attack: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  evidence: string[];
}

export interface PeSecurityVerdict {
  verdict: 'Malicious' | 'Suspicious' | 'Potentially Vulnerable' | 'No Known Threat Detected' | 'Inconclusive';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  confidence_score: number;
  rationale: string[];
  mitre_techniques: Array<{ id: string; name: string; tactic: string }>;
  containment_recommendations: string[];
}

export interface DllForensics {
  is_dll: boolean;
  export_count: number;
  forwarded_export_count: number;
  has_proxy_exports: boolean;
  forwarded_exports: Array<{
    name: string;
    ordinal: number;
    address?: string;
    forwarder?: string;
    is_forwarded?: boolean;
  }>;
  tls_callbacks: Array<{
    index: number;
    va: string;
    rva: string;
    section: string;
    description: string;
  }>;
  has_tls_callbacks: boolean;
  sideloading_risk: {
    is_common_target_dll: boolean;
    target_match_name?: string | null;
    risk_level: string;
    description: string;
    common_host_processes: string[];
  };
}

export interface DotNetAssemblyForensics {
  is_dotnet: boolean;
  runtime_version?: string | null;
  target_framework?: string | null;
  assembly_name?: string | null;
  flags?: string[];
  entry_point_token?: string | null;
  is_il_only?: boolean;
  is_32bit_required?: boolean;
  is_strong_name_signed?: boolean;
  suspicious_features: Array<{
    category: string;
    api: string;
    severity: string;
    description: string;
  }>;
  detected_obfuscators: string[];
}

export interface PeVulnerabilityForensics {
  vulnerability_count: number;
  has_wx_sections: boolean;
  wx_sections: string[];
  missing_mitigations: string[];
  legacy_crt_apis: Array<{
    api: string;
    cwe: string;
    severity: string;
    vulnerability_type: string;
    description: string;
    replacement: string;
  }>;
  risk_score: number;
}

export interface PeOverlayForensics {
  has_overlay: boolean;
  size: number;
  entropy: number;
  classified_type: string;
  hex_preview: string;
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

export interface EvtxVerdict {
  verdict: 'Malicious' | 'Suspicious' | 'Potentially Vulnerable' | 'No Known Threat Detected' | 'Inconclusive' | string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence_score: number;
  key_assessment_rationale: string[];
  mitre_attack_techniques: string[];
  containment_guidance: string[];
  coverage_score?: number;
  coverage_warning?: string | null;
}

export interface EvtxCaptureIntegrity {
  filename: string;
  format: string;
  is_valid_evtx: boolean;
  is_binary_evtx: boolean;
  is_xml_export: boolean;
  file_size: number;
  file_hashes: {
    sha256: string;
    sha1: string;
    md5: string;
  };
  evtx_header: {
    major_version: number;
    minor_version: number;
    header_chunk_count: number;
    first_chunk_number: number;
    last_chunk_number: number;
    next_record_id: number;
    header_size: number;
    header_state: string;
    flags: number;
  };
  integrity_status: string;
  continuity?: {
    total_records: number;
    record_id_gaps: Array<{
      from_record_id: number;
      to_record_id: number;
      missing_count: number;
      severity: string;
      note: string;
    }>;
    timestamp_gaps: Array<{
      from_timestamp: string;
      to_timestamp: string;
      gap_duration_hours: number;
      severity: string;
      note: string;
    }>;
    has_continuity_anomalies: boolean;
  };
}

export interface EvtxCoverageAudit {
  coverage_score: number;
  channels_present_count: number;
  channels_present: string[];
  catalog_audit: Array<{
    channel: string;
    role: string;
    importance: 'critical' | 'high' | 'medium' | 'low';
    present: boolean;
  }>;
  missing_critical_channels: string[];
  coverage_limitations: string[];
}

export interface EvtxSigmaAlert {
  rule_id: string;
  title: string;
  level: 'critical' | 'high' | 'medium' | 'low';
  tags: string[];
  mitre_technique: string;
  description: string;
  author: string;
  match_count: number;
  sample_events: Array<{
    event_id: number;
    timestamp: string;
    user: string;
    computer: string;
    command_line?: string;
    summary?: string;
  }>;
}

export interface EvtxAuthForensics {
  logon_types_breakdown: Record<string, number>;
  total_successful_logons: number;
  total_failed_logons: number;
  failed_by_user: Record<string, number>;
  failed_by_ip: Record<string, number>;
  status_code_audit: Array<{
    code: string;
    count: number;
    meaning: string;
    threat: string;
  }>;
  password_spray_sources: Array<{
    source_ip: string;
    targeted_accounts_count: number;
    targeted_accounts: string[];
    failed_count: number;
  }>;
  brute_force_success: Array<{
    target_account: string;
    failure_count: number;
    first_failure: string;
    successful_logon: string;
  }>;
  explicit_credentials_logons: Array<any>;
  special_privileges_logons: Array<any>;
  kerberos_forensics: {
    tgt_requests_count: number;
    service_tickets_count: number;
    kerberoasting_candidates: Array<{
      timestamp: string;
      service_name: string;
      account: string;
      ip: string;
      encryption_type: string;
    }>;
    kerberos_preauth_failures: Array<{
      timestamp: string;
      account: string;
      ip: string;
      status: string;
    }>;
  };
}

export interface EvtxAccountManagement {
  users_created: Array<{
    timestamp: string;
    actor: string;
    created_user: string;
    details?: Record<string, any>;
  }>;
  users_enabled: Array<{
    timestamp: string;
    actor: string;
    enabled_user: string;
  }>;
  password_resets: Array<{
    timestamp: string;
    actor: string;
    target_account: string;
    is_admin_reset: boolean;
  }>;
  users_deleted: Array<{
    timestamp: string;
    actor: string;
    deleted_user: string;
  }>;
  sensitive_group_additions: Array<{
    timestamp: string;
    actor: string;
    member_added: string;
    group_name: string;
    group_sid: string;
    is_sensitive_group: boolean;
    event_id: number;
  }>;
  user_rights_assigned: Array<{
    timestamp: string;
    actor: string;
    target_account: string;
    rights: string;
  }>;
}

export interface EvtxLateralChain {
  target_host: string;
  stages_detected: string[];
  stages_count: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  sample_actor: string;
  source_ip: string;
  payload_dropped?: string | null;
  summary: string;
}

export interface EvtxTamperingAnalysis {
  tampering_detected: boolean;
  total_tampering_events: number;
  logs_cleared: Array<{
    timestamp: string;
    event_id: number;
    log_type: string;
    user: string;
    computer: string;
  }>;
  audit_policy_changes: Array<any>;
  service_interruptions: Array<any>;
  system_time_manipulations: Array<any>;
  defender_tampering: Array<any>;
  sysmon_tampering: Array<any>;
}

export interface EvtxOfflineToolsGuide {
  evtxecmd?: { title: string; purpose: string; command: string; notes: string };
  chainsaw?: { title: string; purpose: string; command: string; notes: string };
  hayabusa?: { title: string; purpose: string; command: string; notes: string };
  powershell_getwinevent?: { title: string; purpose: string; command: string; notes: string };
  wevtutil?: { title: string; purpose: string; command: string; notes: string };
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
  evtx_verdict?: EvtxVerdict;
  capture_integrity?: EvtxCaptureIntegrity;
  coverage_audit?: EvtxCoverageAudit;
  sigma_alerts?: EvtxSigmaAlert[];
  auth_forensics?: EvtxAuthForensics;
  account_management?: EvtxAccountManagement;
  lateral_chains?: EvtxLateralChain[];
  tampering_analysis?: EvtxTamperingAnalysis;
  offline_tools_guide?: EvtxOfflineToolsGuide;
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
  mraptor?: {
    suspicious: boolean;
    flags: string;
    autoexec: boolean;
    autoexec_match?: string | null;
    write: boolean;
    write_match?: string | null;
    execute: boolean;
    execute_match?: string | null;
    matches: string[];
  };
  oleid_indicators?: Array<{
    id: string;
    name: string;
    type: string;
    value: string;
    description?: string;
    risk: string;
  }>;
  xlm_macros?: { has_xlm_macros: boolean; details?: string[] };
  rtf_exploits?: { is_rtf: boolean; has_exploits: boolean; details?: string[]; carved_payloads?: string[] };
  rtf_objects?: Array<{
    id: number;
    format_id: number;
    class_name: string;
    size: number;
    is_package: boolean;
    filename?: string;
    src_path?: string;
    temp_path?: string;
    clsid?: string;
    clsid_desc?: string;
    carved_type?: string;
    carved_size?: number;
    carved_sha256?: string;
    suspicious?: boolean;
  }>;
  ole_forensics?: {
    is_ole_file?: boolean;
    sector_size?: number;
    minisector_size?: number;
    streams_count?: number;
    total_edit_time_minutes?: number;
    streams?: Array<{
      path: string;
      type: string;
      size: number;
      ctime?: string | null;
      mtime?: string | null;
      clsid?: string | null;
    }>;
    clsids?: string[];
    anomalies?: string[];
  };
  onenote_analysis?: {
    is_onenote: boolean;
    embedded_attachments: Array<{
      filename: string;
      file_type: string;
      size: number;
      sha256: string;
      suspicious: boolean;
      offset?: number;
    }>;
    suspicious_extensions: string[];
  };
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
  entropy?: number;
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

export interface PdfStructureForensics {
  total_size: number;
  header_offset: number;
  is_polyglot: boolean;
  polyglot_type?: string;
  eof_count: number;
  eof_offsets?: number[];
  startxref_offsets?: number[];
  has_overlay: boolean;
  overlay_size?: number;
  overlay_entropy?: number;
  overlay_hex?: string;
  overlay_threat?: string;
  overlay_desc?: string;
}

export interface PdfDigitalSignatureItem {
  xref: number;
  subfilter: string;
  signer: string;
  reason: string;
  date: string;
  byte_range: number[];
  has_shadow_attack: boolean;
  shadow_bytes_count: number;
}

export interface PdfConcealedSpan {
  page: number;
  text: string;
  color_hex?: string;
  size: number;
  font?: string;
  bbox: number[];
  page_rect?: number[];
}

export interface PdfDeceptiveLink {
  page: number;
  display_text: string;
  display_domain: string;
  destination_uri: string;
  target_domain: string;
  rect: number[];
}

export interface PdfConcealedContent {
  white_text_count: number;
  white_text_spans: PdfConcealedSpan[];
  tiny_font_count: number;
  tiny_font_spans: PdfConcealedSpan[];
  off_page_count: number;
  off_page_spans: PdfConcealedSpan[];
  has_invisible_render_mode: boolean;
  deceptive_link_count: number;
  deceptive_links: PdfDeceptiveLink[];
  has_ocg: boolean;
  ocg_layers: string[];
}

export interface PdfActionChainItem {
  trigger_hook: string;
  scope: string;
  action_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  raw_snippet: string;
}

export interface PdfCarvedAttachment {
  id: number;
  filename: string;
  size: number;
  size_formatted: string;
  sha256: string;
  classification: string;
  is_threat: boolean;
  threat_level: 'critical' | 'high' | 'suspicious' | 'neutral' | string;
  description?: string;
  hex_preview?: string;
}

export interface PdfDangerousJsApi {
  api: string;
  risk: string;
  description: string;
  mitre?: string;
}

export interface PdfJsAnalysis {
  has_javascript: boolean;
  deobfuscated_code: string;
  deobfuscated_applied: boolean;
  dangerous_apis: PdfDangerousJsApi[];
  shellcode_indicators: string[];
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
  structure_forensics?: PdfStructureForensics;
  digital_signatures?: PdfDigitalSignatureItem[];
  concealed_content?: PdfConcealedContent;
  action_chains?: PdfActionChainItem[];
  carved_attachments?: PdfCarvedAttachment[];
  js_analysis?: PdfJsAnalysis;
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

export interface JarClassEntry {
  class_name: string;
  class_file: string;
  is_entry: boolean;
  methods_count: number;
  fields_count: number;
  methods: Array<{
    name: string;
    descriptor?: string;
    access_flags?: number;
    signature?: string;
  }>;
  fields: Array<{
    name: string;
    descriptor?: string;
    access_flags?: number;
    formatted?: string;
  }>;
  decompiled_source: string;
}

export interface JarSigningInfo {
  is_signed: boolean;
  status: string;
  certificate?: {
    subject: string;
    issuer: string;
    valid_from: string;
    valid_to: string;
    is_self_signed: boolean;
    is_expired: boolean;
    is_debug_key: boolean;
    fingerprint_sha256: string;
    serial_number?: string;
  };
  signature_files?: string[];
  is_partially_signed?: boolean;
  unsigned_classes_count?: number;
  unsigned_classes?: string[];
}

export interface JarArchiveSecurity {
  zip_slip: {
    detected: boolean;
    paths: string[];
    count: number;
  };
  zip_bomb: {
    detected: boolean;
    compression_ratio: number;
    uncompressed_size: number;
    compressed_size: number;
    disk_size?: number;
    is_dangerous: boolean;
  };
  duplicate_entries: {
    detected: boolean;
    entries: string[];
    count: number;
  };
  extension_mismatches: Array<{
    filename: string;
    declared_extension: string;
    actual_type: string;
    file_size: number;
    threat_level: string;
  }>;
  polyglot_and_trailing: {
    has_trailing_data: boolean;
    trailing_bytes_count: number;
    has_leading_polyglot: boolean;
    leading_magic: string;
  };
  nested_archives: Array<{
    filename: string;
    size: number;
    type: string;
  }>;
  issues_count: number;
  verdict: 'SECURE' | 'SUSPICIOUS' | 'VULNERABLE';
}

export interface JarDependency {
  group_id: string;
  artifact_id: string;
  version: string;
  source: string;
  type: string;
}

export interface JarShadedLibrary {
  name: string;
  package_prefix: string;
  category: string;
  packages_count: number;
}

export interface JarCveAdvisory {
  artifact: string;
  version: string;
  cve: string;
  name: string;
  severity: string;
  cvss: number;
  cwe: string;
  description: string;
}

export interface JarCycloneDxSbom {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: Array<{ vendor: string; name: string; version: string }>;
    component: {
      name: string;
      version: string;
      type: string;
    };
  };
  components: Array<{
    type: string;
    group?: string;
    name: string;
    version?: string;
    purl?: string;
    cpe?: string;
    description?: string;
    scope?: string;
  }>;
  multi_release?: {
    is_multi_release: boolean;
    versions: number[];
  };
}

export interface JarSecretsAndCtf {
  detected: boolean;
  ctf_flags: Array<{
    flag: string;
    format: string;
    length: number;
    source?: string;
  }>;
  flags_count: number;
  secrets: Array<{
    type: string;
    masked: string;
    severity: string;
    description: string;
    length: number;
  }>;
  secrets_count: number;
}

export interface JarEmbeddedResource {
  name: string;
  size: number;
  type: string;
  is_executable: boolean;
  is_script: boolean;
  is_archive: boolean;
  is_config: boolean;
  threat_level: 'SUSPICIOUS' | 'DANGEROUS' | 'INFO';
}

export interface JarLolbinMatch {
  name: string;
  category: string;
  description: string;
  matched_in: string;
  matched_text: string;
}

export interface JarBase64Block {
  encoded: string;
  encoded_full: string;
  decoded_preview: string;
  encoding: string;
  length: number;
  threat: string;
  iocs?: string[];
}

export interface JarTriageInfo {
  is_jar: boolean;
  main_class?: string | null;
  permissions?: string | null;
  manifest_content?: string;
  class_count: number;
  classes_count?: number;
  embedded_binaries?: string[];
  packages?: string[];
  total_entries?: number;
  suspicious_apis?: Array<{
    class_file: string;
    api: string;
    title?: string;
    severity?: string;
    category?: string;
    description: string;
    risk_explanation?: string;
    remediation?: string;
    cwe?: string;
    owasp?: string;
    mitre?: string;
    mitre_name?: string;
  }>;
  dangerous_apis?: Array<{
    class_file: string;
    api: string;
    title?: string;
    severity?: string;
    category?: string;
    description: string;
    risk_explanation?: string;
    remediation?: string;
    cwe?: string;
    owasp?: string;
    mitre?: string;
    mitre_name?: string;
  }>;
  behavioral_analysis?: JavaBehavioralAnalysis;
  strrat_profile?: JavaStrratHeuristics;
  rat_detections?: string[];
  iocs?: {
    urls?: string[];
    ips?: string[];
  };
  classes_decompiled?: JarClassEntry[];
  code_modules?: Array<{
    name: string;
    code: string;
    language?: string;
  }>;
  strings?: {
    all_sample: string[];
    categorized: {
      network: string[];
      file_paths: string[];
      registry: string[];
      commands: string[];
      all_sample: string[];
    };
    total_count: number;
  };
  b64_blocks?: JarBase64Block[];
  lolbin_matches?: JarLolbinMatch[];
  has_lolbins?: boolean;
  detected_commands?: string[];
  digital_signature?: {
    is_signed: boolean;
    status: string;
    signer?: string;
    algorithm?: string;
  };
  signing_info?: JarSigningInfo;
  embedded_resources?: JarEmbeddedResource[];
  class_info?: {
    major_version?: number;
    minor_version?: number;
    java_version?: string;
    constant_pool_count?: number;
    methods_count?: number;
    interfaces_count?: number;
  };
  code_preview?: string;
  archive_security?: JarArchiveSecurity;
  dependencies?: JarDependency[];
  shaded_libraries?: JarShadedLibrary[];
  cve_advisories?: JarCveAdvisory[];
  cyclonedx_sbom?: JarCycloneDxSbom;
  secrets_and_ctf?: JarSecretsAndCtf;
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
    cipher_suites_audit?: CipherSuitesAudit;
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
      shodan?: { queried: boolean; configured: boolean; verdict: string; open_ports: number[]; cves: string[]; web_link: string };
    };
    cached?: boolean;
    _cache_info?: ApiCacheInfo;
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

  indicator_normalisation?: IndicatorNormalisation;
  dns_configuration_audit?: DnsConfigurationAudit;
  subdomain_takeover_analysis?: SubdomainTakeoverAnalysis;
  email_domain_posture?: EmailDomainPosture;
  tls_cert_forensics?: TlsCertForensics;
  web_headers_and_exposure?: WebHeadersAndExposure;
  checklist_verdict?: IpDomainChecklistVerdict;
  offline_tools_guide?: OfflineToolsGuide;
  active_recon_summary?: {
    dns_findings?: string[];
    rdap_findings?: string[];
    tls_findings?: string[];
    http_findings?: string[];
    ip_findings?: string[];
  };
  shodan?: ShodanResult;
  dork_findings?: DorkArtifactFindings;
}

export interface ApiCacheInfo {
  cached: boolean;
  cached_at?: string;
  cached_at_epoch?: number;
  age_seconds?: number;
  age_hours?: number;
  age_days?: number;
  age_human?: string;
  service?: string;
  max_age_limit_hours?: number;
  mode?: string;
  stale_fallback?: boolean;
}

export interface ShodanService {
  port: number;
  transport: string;
  product?: string | null;
  version?: string | null;
  cpe?: string[];
  banner_snippet?: string | null;
  raw_banner?: string | null;
  ssl_enabled: boolean;
  cloud?: { provider?: string; region?: string; service?: string } | null;
  http?: {
    title?: string | null;
    server?: string | null;
    dom_hash?: number | null;
    favicon_hash?: number | string | null;
    cookies?: string[] | null;
    security_headers?: string[] | null;
  } | null;
  ssl?: {
    enabled?: boolean;
    cert_subject?: string | null;
    cert_issuer?: string | null;
    cipher?: string | null;
  } | null;
  vulns?: string[];
}

export interface ShodanHost {
  ip: string;
  port?: number;
  transport?: string;
  hostnames: string[];
  domains?: string[];
  org?: string | null;
  isp?: string | null;
  asn?: string | null;
  city?: string | null;
  country_name?: string | null;
  country_code?: string | null;
  cloud?: { provider?: string; region?: string; service?: string } | null;
  cloud_providers?: string[];
  os?: string | null;
  product?: string | null;
  version?: string | null;
  banner_snippet?: string | null;
  raw_banner?: string | null;
  services?: ShodanService[];
  http?: {
    title?: string | null;
    server?: string | null;
    dom_hash?: number | null;
    favicon_hash?: number | string | null;
    cookies?: string[] | null;
    security_headers?: string[] | null;
  } | null;
  ssl?: {
    enabled?: boolean;
    cert_subject?: string | null;
    cert_issuer?: string | null;
    cipher?: string | null;
  } | null;
  vulns: string[];
  ports?: number[];
}

export interface ShodanResult {
  configured: boolean;
  queried: boolean;
  target: string;
  is_ip: boolean;
  web_link: string;
  ports?: number[];
  vulns?: string[];
  services?: ShodanService[];
  tags?: string[];
  hostnames?: string[];
  os?: string | null;
  isp?: string | null;
  org?: string | null;
  asn?: string | null;
  city?: string | null;
  country_name?: string | null;
  country_code?: string | null;
  last_update?: string | null;
  total_services?: number;
  total_hosts?: number;
  cloud_providers?: string[];
  subdomains?: string[];
  dns_records?: Array<{ subdomain?: string; sub?: string; type: string; value: string; last_seen?: string }>;
  hosts?: ShodanHost[];
  primary_ip_telemetry?: any;
  message?: string;
  cached?: boolean;
  _cache_info?: ApiCacheInfo;
}

export interface SensitiveArtifactItem {
  url: string;
  filename: string;
  extension: string;
  title: string;
  category: 'document' | 'secret' | 'database' | 'log' | 'admin' | 'other' | string;
  category_label: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  snippet?: string | null;
  status_code?: number | null;
  content_length?: number | null;
}

export interface GoogleDorkPreset {
  id: string;
  category: string;
  title: string;
  query: string;
  google_url: string;
  description: string;
}

export interface DorkArtifactFindings {
  scanned: boolean;
  target: string;
  total_artifacts_found: number;
  category_counts: {
    documents: number;
    secrets: number;
    database: number;
    logs: number;
    admin: number;
    other: number;
  };
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  artifacts: SensitiveArtifactItem[];
  dork_presets: GoogleDorkPreset[];
  message?: string;
  cached?: boolean;
  _cache_info?: ApiCacheInfo;
}

export interface IndicatorNormalisation {
  original_input: string;
  normalized_value: string;
  indicator_type: string;
  is_valid: boolean;
  ip_classification?: string;
  is_private_rfc1918?: boolean;
  is_loopback?: boolean;
  is_link_local?: boolean;
  is_multicast?: boolean;
  is_reserved?: boolean;
  is_cgnat?: boolean;
  is_documentation?: boolean;
  is_mapped_v6?: boolean;
  mapped_ipv4?: string | null;
  rdns_eligible: boolean;
  rdns_eligibility_reason: string;
  has_punycode?: boolean;
  is_punycode?: boolean;
  is_homograph?: boolean;
  unicode_rendered?: string;
  spoofed_chars?: Array<{
    char: string;
    latin_lookalike: string;
    codepoint: string;
    name: string;
  }>;
  subdomain?: string | null;
  registrable_domain?: string | null;
  public_suffix?: string | null;
  is_special_use_domain?: boolean;
  special_use_category?: string | null;
  is_dns_eligible?: boolean;
  dns_eligibility_reason?: string;
  ssrf_risk?: boolean;
  ssrf_mitigation_note?: string;
  active_ipaddress_findings?: string[];
}

export interface DnsConfigurationAudit {
  counts: Record<string, number>;
  dnssec: {
    enabled: boolean;
    validated: boolean;
    ds_records: any[];
    dnskey_count: number;
    notes: string;
  };
  has_wildcard_dns: boolean;
  wildcard_ip: string | null;
  low_ttl_detected: boolean;
  min_ttl: number | null;
  fast_flux_suspect: boolean;
  cname_chain: string[];
  anomalies: Array<{
    type: string;
    severity: string;
    title: string;
    description: string;
  }>;
  active_dig_findings?: string[];
}

export interface SubdomainTakeoverCandidate {
  domain: string;
  cname_target: string;
  provider: string;
  status: string;
  severity: string;
  vulnerability: string;
  fingerprint_match?: string;
  description: string;
  remediation: string;
}

export interface SubdomainTakeoverAnalysis {
  evaluated_count?: number;
  vulnerable_count?: number;
  has_high_risk_takeover?: boolean;
  candidates?: SubdomainTakeoverCandidate[];
  summary?: string;
  has_takeover_risk?: boolean;
  claimable_count?: number;
  dangling_cnames?: Array<{
    subdomain: string;
    cname_target: string;
    service_provider: string;
    signature: string;
    takeover_status: string;
    severity: string;
    remediation: string;
  }>;
  remediation_guidance?: string[];
}

export interface EmailDomainPosture {
  domain?: string;
  is_spoofable?: boolean;
  spoofing_risk_summary?: string;
  spf: {
    present?: boolean;
    published?: boolean;
    raw?: string | null;
    raw_record?: string | null;
    qualifier: string;
    all_qualifier?: string;
    qualifier_safety: string;
    lookup_count: number;
    lookup_limit_exceeded: boolean;
    is_permissive?: boolean;
    issues?: string[];
  };
  dmarc: {
    present?: boolean;
    published?: boolean;
    raw?: string | null;
    policy: string;
    is_enforced: boolean;
    subdomain_policy: string | null;
    percentage?: number;
    aggregate_reports?: string[];
    vulnerable_to_spoofing?: boolean;
    issues?: string[];
  };
  dkim: {
    selectors_checked: number;
    selectors_found: any[];
  };
  mta_sts: {
    enabled: boolean;
    published?: boolean;
    mode?: string | null;
  };
  tls_rpt: {
    enabled: boolean;
    published?: boolean;
  };
  has_mx?: boolean;
  has_null_mx?: boolean;
  null_mx?: boolean;
  overall_posture: string;
  findings?: Array<{
    severity: string;
    title: string;
    description: string;
  }>;
}

export interface HostnameValidationDetails {
  matches: boolean;
  status: 'MATCH' | 'MISMATCH';
  target: string;
  subject_cn?: string | null;
  matched_pattern?: string | null;
  match_type: 'EXACT_SAN' | 'WILDCARD_SAN' | 'EXACT_IP_SAN' | 'CN_FALLBACK' | 'NONE';
  mismatch_type?: 'IP_WITHOUT_IP_SAN' | 'WILDCARD_DEPTH_EXCEEDED' | 'CN_ONLY_IGNORED' | 'UNRELATED_DOMAIN' | 'CDN_SNI_MISCONFIGURATION' | 'NO_CERTIFICATE' | null;
  how: string;
  why: string;
  risk_level: 'none' | 'low' | 'medium' | 'high';
  remediation: string;
}

export interface SupportedCipherEntry {
  name: string;
  protocol: string;
  key_exchange: string;
  encryption: string;
  mac: string;
  bits: number;
  status: 'RECOMMENDED' | 'ACCEPTABLE' | 'WEAK' | 'INSECURE' | 'BROKEN';
  is_weak: boolean;
  supported: boolean;
  active_negotiated: boolean;
  explanation: string;
}

export interface CipherSuitesAudit {
  active_cipher?: string | null;
  active_protocol?: string | null;
  total_cataloged: number;
  supported_count: number;
  weak_ciphers_count: number;
  has_weak_ciphers: boolean;
  weak_ciphers: SupportedCipherEntry[];
  ciphers: SupportedCipherEntry[];
}

export interface TlsCertForensics {
  has_tls: boolean;
  subject_cn?: string;
  issuer_cn?: string;
  issuer?: string;
  issuer_org?: string;
  sans: string[];
  sans_count?: number;
  is_wildcard: boolean;
  matches_target: boolean;
  hostname_matches_cert?: boolean;
  days_remaining?: number;
  days_to_expiry?: number;
  is_expired: boolean;
  is_self_signed: boolean;
  signature_algorithm?: string;
  key_type?: string;
  key_size?: number;
  ct_log_count: number;
  ct_logs_count?: number;
  sha256_fingerprint?: string;
  hostname_validation?: HostnameValidationDetails;
  cipher_suites_audit?: CipherSuitesAudit;
  active_openssl_findings?: string[];
  warnings?: Array<{
    severity: string;
    title: string;
    description: string;
  }>;
  findings: Array<{
    severity: string;
    title: string;
    description: string;
  }>;
}

export interface WebHeadersAndExposure {
  status_code: number | null;
  server_banner: string | null;
  powered_by: string | null;
  headers_audit: {
    hsts: boolean;
    csp: boolean;
    x_frame_options: boolean;
    x_content_type_options: boolean;
    referrer_policy: boolean;
    permissions_policy: boolean;
  };
  missing_security_headers: string[];
  exposed_sensitive_files: Array<{
    path: string;
    title: string;
    category: string;
    risk: string;
    status_code: number;
    content_preview?: string;
  }>;
  findings: Array<{
    severity: string;
    title: string;
    description: string;
  }>;
  active_curl_findings?: string[];
}

export interface IpDomainChecklistVerdict {
  verdict: 'Malicious' | 'Suspicious' | 'Vulnerable / Misconfigured' | 'Benign / Low Risk' | 'Clean / Benign' | 'Clean / Informational' | 'Private / Internal Indicator' | string;
  risk_score: number;
  confidence_score: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'info' | string;
  threat_tags: string[];
  rationale: string[];
  mitre_techniques?: Array<{ id: string; name: string }>;
  mitre_attack?: string[];
  containment_checklist: string[];
  risk_breakdown?: {
    threat_intelligence: {
      score: number;
      max_score?: number;
      weight_pct: number;
      level: string;
      summary: string;
      factors: Array<{ name: string; points: number; type: 'penalty' | 'credit' | 'neutral'; detail: string }>;
    };
    infrastructure_reputation: {
      score: number;
      max_score?: number;
      weight_pct: number;
      level: string;
      summary: string;
      factors: Array<{ name: string; points: number; type: 'penalty' | 'credit' | 'neutral'; detail: string }>;
    };
    cryptographic_trust: {
      score: number;
      max_score?: number;
      weight_pct: number;
      level: string;
      summary: string;
      factors: Array<{ name: string; points: number; type: 'penalty' | 'credit' | 'neutral'; detail: string }>;
    };
    exposure_and_hardening: {
      score: number;
      max_score?: number;
      weight_pct: number;
      level: string;
      summary: string;
      factors: Array<{ name: string; points: number; type: 'penalty' | 'credit' | 'neutral'; detail: string }>;
    };
    summary_explanation: string;
  };
}

export interface OfflineToolItem {
  name: string;
  tool?: string;
  command: string;
  purpose: string;
  category: string;
  description?: string;
  executed?: boolean;
  status?: 'success' | 'warning' | 'error' | string;
  exit_code?: number;
  duration_ms?: number;
  stdout?: string;
  stderr?: string | null;
  parsed_findings?: string[];
}

export interface OfflineToolsGuide {
  disclaimer: string;
  executed_live?: boolean;
  tools: OfflineToolItem[];
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
  groupedCount?: number;
  groupedVariants?: string[];
  groupedNodes?: any[];
  // Hierarchy & Parent-Child Tree Fields
  parentId?: string | null;
  parentLabel?: string | null;
  parentType?: string | null;
  isChild?: boolean;
  childIds?: string[];
  childrenCount?: number;
  childNodes?: EntityGraphNode[];
  treeLevel?: number;
  hierarchyRelation?: 'child_endpoint' | 'subdomain' | 'service_port' | 'child_process' | 'embedded_content' | string;
  is_shared?: boolean;
}

export interface EntityGraphEdge {
  source: string;
  target: string;
  label: string;
  type: string;
  is_hierarchy?: boolean;
  is_shared?: boolean;
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
    email_artifacts_count?: number;
    forensic_count?: number;
    cross_log_pivots_count?: number;
  };
}

export interface EntityGroupBox {
  id: string;
  title: string;
  color: string;
  x: number;
  y: number;
  width: number;
  height: number;
  nodeIds: string[];
  originalPositions: Record<string, { x: number; y: number }>;
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

export interface PcapVerdict {
  verdict: 'Malicious' | 'Suspicious' | 'Potentially Vulnerable' | 'No Known Threat Detected' | 'Inconclusive';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  confidence_score: number;
  rationale: string[];
  mitre_techniques: Array<{ id: string; name: string }>;
  containment_recommendations: string[];
}

export interface PcapTimeGap {
  start_sec: number;
  end_sec: number;
  duration_sec: number;
  severity: 'CRITICAL' | 'WARNING';
}

export interface PcapProvenance {
  sha256: string;
  sha1: string;
  md5: string;
  preservation: string;
  analysis_engine: string;
}

export interface PcapCaptureIntegrity {
  format: string;
  is_pcapng: boolean;
  magic_hex: string;
  endianness: string;
  timestamp_precision: string;
  link_layer_types: string[];
  packet_count: number;
  total_file_bytes: number;
  duration_seconds: number;
  start_time: string | null;
  end_time: string | null;
  integrity_status: string;
  integrity_issues: string[];
  truncated_packets_count: number;
  undersized_frames_count: number;
  jumbo_frames_count: number;
  duplicate_packets_count: number;
  tcp_retransmissions_count: number;
  time_gaps: PcapTimeGap[];
  provenance: PcapProvenance;
}

export interface ZeekConnLog {
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  proto: string;
  service: string;
  duration: number;
  orig_bytes: number;
  resp_bytes: number;
  conn_state: string;
  local_orig: boolean;
  local_resp: boolean;
  history: string;
}

export interface ZeekDnsLog {
  uid: string;
  id_orig_h: string;
  id_resp_h: string;
  proto: string;
  query: string;
  qtype_name: string;
  rcode_name: string;
  answers: string[];
  TTLs: number[];
  rejected: boolean;
  entropy: number;
  is_suspicious: boolean;
}

export interface ZeekSslLog {
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  version: string;
  cipher: string;
  server_name: string;
  ja3?: string;
  ja3s?: string;
  established: boolean;
  subject: string;
  issuer: string;
}

export interface ZeekX509Log {
  certificate_serial: string;
  subject: string;
  issuer: string;
  san_dns: string[];
  validity_start: string;
  validity_end: string;
  key_type: string;
  key_length: number;
  self_signed: boolean;
  is_expired: boolean;
}

export interface ZeekFilesLog {
  fuid: string;
  source_proto: string;
  mime_type: string;
  filename: string;
  total_bytes: number;
  sha256: string;
  is_dangerous: boolean;
  threat_category: string;
}

export interface ZeekStructuredLogs {
  conn_log: ZeekConnLog[];
  dns_log: ZeekDnsLog[];
  ssl_log: ZeekSslLog[];
  x509_log: ZeekX509Log[];
  files_log: ZeekFilesLog[];
}

export interface SuricataAlert {
  sid: number;
  classtype: string;
  severity: number;
  severity_label: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  msg: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  matched_snippet: string;
}

export interface DgaCandidate {
  domain: string;
  subdomain: string;
  entropy: number;
  length: number;
  client_ip: string;
  resolved_ips: string[];
  threat_note: string;
}

export interface DnsTunnelingQuery {
  domain: string;
  query_type: string;
  entropy: number;
  client_ip: string;
  reason: string;
}

export interface FastFluxDomain {
  domain: string;
  resolved_ips: string[];
  unique_subnets: number;
  risk_assessment: string;
}

export interface PcapDnsForensics {
  total_queries_analyzed: number;
  nxdomain_count: number;
  nxdomain_ratio_percent: number;
  nxdomain_burst_detected: boolean;
  dga_candidates: DgaCandidate[];
  tunneling_queries: DnsTunnelingQuery[];
  fast_flux_domains: FastFluxDomain[];
  top_queried_slds: Array<{ sld: string; count: number }>;
}

export interface PcapBeaconSession {
  source_ip: string;
  target_ip: string;
  target_scope: string;
  pulse_count: number;
  mean_interval_sec: number;
  std_dev_sec: number;
  jitter_percent: number;
  classification: string;
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  min_interval: number;
  max_interval: number;
}

export interface PcapBeaconingAnalysis {
  detected_beacon_count: number;
  beaconing_sessions: PcapBeaconSession[];
}

export interface PcapRatioAnomaly {
  flow_id: string;
  source_ip: string;
  target_ip: string;
  target_port: number;
  client_upload_bytes: number;
  server_download_bytes: number;
  upload_ratio: number;
  protocol: string;
  threat_note: string;
}

export interface PcapIcmpTunnelPacket {
  source_ip: string;
  target_ip: string;
  icmp_type: string;
  payload_size: number;
  payload_entropy: number;
  reason: string;
  hex_preview: string;
}

export interface PcapCloudExfilEvent {
  service: string;
  target_url: string;
  method: string;
  source_ip: string;
  destination_ip: string;
  threat_note: string;
}

export interface PcapExfiltrationAnalysis {
  ratio_anomalies: PcapRatioAnomaly[];
  icmp_tunneling_packets: PcapIcmpTunnelPacket[];
  cloud_exfiltration_events: PcapCloudExfilEvent[];
  has_high_confidence_exfiltration: boolean;
}

export interface PcapReconScan {
  scanner_ip: string;
  target_ip?: string;
  target_count?: number;
  scan_type: string;
  ports_probed_count?: number;
  ports_sample?: number[];
  sample_targets?: string[];
  threat_level: 'HIGH' | 'MEDIUM';
}

export interface PcapLateralEvent {
  source_ip: string;
  destination_ip: string;
  target_port: number;
  protocol_name: string;
  admin_share?: string | null;
  bytes_transferred: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface PcapLateralMovement {
  scans_detected: PcapReconScan[];
  lateral_movement_events: PcapLateralEvent[];
  has_active_reconnaissance: boolean;
  has_lateral_movement: boolean;
}

export interface PcapArpAlert {
  target_ip: string;
  conflicting_mac_addresses: string[];
  threat_note: string;
}

export interface PcapNtpAmplification {
  source_ip: string;
  type: string;
  size: number;
}

export interface PcapModbusEvent {
  source_ip: string;
  target_ip: string;
  unit_id: number;
  function_code: number;
  operation: string;
  severity: 'CRITICAL' | 'INFO';
}

export interface PcapProtocolAnomalies {
  arp_spoofing_alerts: PcapArpAlert[];
  dhcp_servers_detected: string[];
  rogue_dhcp_detected: boolean;
  ntp_amplifications: PcapNtpAmplification[];
  modbus_industrial_events: PcapModbusEvent[];
  quic_sessions_count: number;
  cleartext_credentials_count: number;
}

export interface PcapInfo {
  pcap_verdict?: PcapVerdict;
  capture_integrity?: PcapCaptureIntegrity;
  zeek_logs?: ZeekStructuredLogs;
  ids_alerts?: SuricataAlert[];
  dns_forensics?: PcapDnsForensics;
  beaconing_analysis?: PcapBeaconingAnalysis;
  exfiltration_analysis?: PcapExfiltrationAnalysis;
  lateral_movement?: PcapLateralMovement;
  protocol_anomalies?: PcapProtocolAnomalies;
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
      groupedCount?: number;
      groupedVariants?: string[];
      groupedNodes?: any[];
      parentId?: string | null;
      parentLabel?: string | null;
      parentType?: string | null;
      isChild?: boolean;
      childIds?: string[];
      childrenCount?: number;
      childNodes?: any[];
      treeLevel?: number;
      hierarchyRelation?: string;
    }>;
    edges: Array<{
      source: string;
      target: string;
      label: string;
      type: string;
      is_shared?: boolean;
      is_hierarchy?: boolean;
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
  authorities?: string;
  label?: string;
  is_main?: boolean;
  is_launcher?: boolean;
  is_boot?: boolean;
  is_sms?: boolean;
  intent_filters?: Array<{
    actions?: string[];
    categories?: string[];
  }> | string[];
  actions?: string[];
}

export interface ApkDetectedApi {
  pattern?: string;
  api: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  risk_explanation?: string;
  remediation?: string;
  cwe?: string;
  owasp_mobile?: string;
  mitre?: string;
  mitre_name?: string;
  count: number;
  evidence: string[];
}

export interface ApkClassMethod {
  name: string;
  descriptor: string;
  access_flags?: string;
  instructions_count?: number;
  instructions?: string[];
  source?: string;
}

export interface ApkClassDetail {
  name: string;
  package: string;
  superclass?: string;
  access_flags?: string;
  methods_count: number;
  methods?: ApkClassMethod[];
  source_code?: string;
}

export interface ApkEmbeddedSourceFile {
  filename: string;
  file_type: 'java' | 'kotlin' | 'javascript' | 'shell' | 'xml' | 'json' | 'other';
  size: number;
  content_preview: string;
  suspicious_findings: string[];
  danger_level: 'clean' | 'suspicious' | 'malicious';
}

export interface ApkNativeSoDetail {
  filename: string;
  architecture: string;
  file_size: number;
  jni_exports?: string[];
  checksec?: {
    nx: boolean;
    pie: boolean;
    canary: boolean;
    relro: string;
  };
  imported_symbols?: string[];
  suspicious_calls?: string[];
}

export interface ApkOnlineIntel {
  sha256: string;
  sha1: string;
  md5: string;
  package_name: string;
  koodous_url: string;
  virustotal_url: string;
  malwarebazaar_url: string;
  google_play_url?: string;
  apkpure_url?: string;
  play_store_status?: 'verified' | 'unlisted_sideloaded' | 'unverified' | 'offline' | string;
  play_store_title?: string;
  play_store_details?: string;
  overall_verdict?: string;
  threat_tags?: string[];
  malware_families?: string[];
  feeds?: Record<string, any>;
  exfiltration_tokens?: {
    telegram_bots?: string[];
    discord_webhooks?: string[];
    firebase_databases?: string[];
  };
  ioc_reputation?: {
    queried_count: number;
    malicious_count: number;
    suspicious_count: number;
    details: Array<{
      indicator: string;
      type: string;
      verdict: string;
      tags: string[];
    }>;
  };
}

export interface ApkPackerInfo {
  is_packed: boolean;
  packer_name?: string;
  matched_markers?: string[];
  description?: string;
}

export interface ApkMalwareSignature {
  family: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  indicators: string[];
}

export interface ApkKeystoreAudit {
  is_aosp_debug_testkey: boolean;
  is_masquerading_identity: boolean;
  masquerade_details?: string;
  validity_anomaly: boolean;
  validity_details?: string;
  janus_vulnerability: boolean;
  janus_details?: string;
}

export interface ApkCategorizedStrings {
  total_count: number;
  urls: string[];
  ips: string[];
  secrets_and_keys: Array<{ type: string; value: string; location?: string }>;
  shell_commands: string[];
  crypto_algorithms: string[];
  sensitive_paths: string[];
  suspicious_apis: string[];
}

export interface ApkSecurityAuditItem {
  check: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  recommendation: string;
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

export interface ApkArchiveSecurity {
  zip_slip: {
    detected: boolean;
    paths: string[];
  };
  decompression_ratio: number;
  zip_bomb_risk: boolean;
  total_uncompressed_bytes: number;
  total_compressed_bytes: number;
  duplicate_entries: {
    detected: boolean;
    entries: string[];
  };
  extension_mismatches: Array<{
    filename: string;
    declared_ext: string;
    actual_type: string;
    magic_hex: string;
    reason: string;
  }>;
  polyglot_and_trailing: {
    has_trailing_data: boolean;
    trailing_bytes_count: number;
    has_prepended_header: boolean;
    prepended_type: string;
    details: string;
  };
  nested_archives: Array<{
    filename: string;
    size: number;
    type: string;
  }>;
  multi_dex_inventory: Array<{
    name: string;
    size: number;
    dex_version: string;
    checksum: string;
    signature: string;
    classes_count: number;
    strings_count: number;
    methods_count: number;
    is_stub: boolean;
  }>;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'VULNERABLE' | string;
}

export interface ApkDependency {
  id: string;
  name: string;
  group: string;
  artifact: string;
  category: string;
  version: string;
  description: string;
  purl: string;
  known_vulnerabilities?: string[];
}

export interface ApkCtfFlag {
  flag: string;
  type: string;
  source: string;
}

export interface ApkHardcodedSecret {
  type: string;
  value: string;
  severity: string;
  source: string;
}

export interface ApkSecretsAndCtf {
  detected: boolean;
  ctf_flags: ApkCtfFlag[];
  secrets: ApkHardcodedSecret[];
  total_count: number;
}

export interface ApkDeepLink {
  activity: string;
  scheme: string;
  host: string;
  path_prefix?: string;
  path_pattern?: string;
  is_custom_scheme: boolean;
  exported: boolean;
}

export interface ApkSensitivePermissionCombo {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  permissions: string[];
  description: string;
  mitre?: string;
  mitre_name?: string;
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
  manifest_xml?: string;
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
  classes?: ApkClassDetail[];
  embedded_source_files?: ApkEmbeddedSourceFile[];
  native_architectures?: string[];
  native_libraries?: string[];
  native_so_details?: ApkNativeSoDetail[];
  categorized_strings?: ApkCategorizedStrings;
  online_intel?: ApkOnlineIntel;
  packer_info?: ApkPackerInfo;
  malware_signatures?: ApkMalwareSignature[];
  keystore_audit?: ApkKeystoreAudit;
  security_audit?: ApkSecurityAuditItem[];
  network_security_config?: {
    found: boolean;
    config_file?: string;
    cleartext_permitted: boolean;
    trusts_user_certs: boolean;
    has_pinning: boolean;
    details: string[];
  };
  archive_security?: ApkArchiveSecurity;
  dependencies?: ApkDependency[];
  cyclonedx_sbom?: Record<string, any>;
  secrets_and_ctf?: ApkSecretsAndCtf;
  deep_links?: ApkDeepLink[];
  sensitive_permission_combos?: ApkSensitivePermissionCombo[];
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
  category?: string;
  description: string;
  risk_explanation?: string;
  remediation?: string;
  cwe?: string;
  owasp?: string;
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
  behavioral_analysis?: JavaBehavioralAnalysis;
  strrat_profile?: JavaStrratHeuristics;
  classes_decompiled?: JarClassEntry[];
  code_modules?: Array<{
    name: string;
    code: string;
    language?: string;
  }>;
  strings?: {
    all_sample: string[];
    categorized: {
      network: string[];
      file_paths: string[];
      registry: string[];
      commands: string[];
      all_sample: string[];
    };
    total_count: number;
  };
  b64_blocks?: JarBase64Block[];
  lolbin_matches?: JarLolbinMatch[];
  has_lolbins?: boolean;
  detected_commands?: string[];
  digital_signature?: {
    is_signed: boolean;
    status: string;
    signer?: string;
    algorithm?: string;
  };
  signing_info?: JarSigningInfo;
  embedded_resources?: JarEmbeddedResource[];
  archive_security?: JarArchiveSecurity;
  dependencies?: JarDependency[];
  shaded_libraries?: JarShadedLibrary[];
  cve_advisories?: JarCveAdvisory[];
  cyclonedx_sbom?: JarCycloneDxSbom;
  secrets_and_ctf?: JarSecretsAndCtf;
}

export interface JavaBehavioralCapability {
  id: string;
  name: string;
  category: 'internet' | 'file' | 'command' | 'obfuscation';
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  evidence: string[];
}

export interface JavaInternetActivity {
  detected: boolean;
  score: number;
  verdict: 'SUSPICIOUS' | 'POTENTIAL' | 'CLEAN';
  summary: string;
  capabilities: JavaBehavioralCapability[];
  endpoints: string[];
}

export interface JavaFileAccess {
  detected: boolean;
  score: number;
  verdict: 'SUSPICIOUS' | 'POTENTIAL' | 'CLEAN';
  summary: string;
  capabilities: JavaBehavioralCapability[];
  targeted_paths: string[];
}

export interface JavaCommandExecution {
  detected: boolean;
  score: number;
  verdict: 'SUSPICIOUS' | 'POTENTIAL' | 'CLEAN';
  summary: string;
  capabilities: JavaBehavioralCapability[];
  detected_commands: string[];
}

export interface JavaObfuscationIndicator {
  type: string;
  name: string;
  severity: string;
  detail: string;
}

export interface JavaStrratHeuristics {
  is_strrat_candidate: boolean;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  matched_indicators: string[];
  explanation?: string;
}

export interface JavaCodeObfuscation {
  is_obfuscated: boolean;
  score: number;
  verdict: 'OBFUSCATED' | 'SUSPICIOUS' | 'CLEAN';
  summary: string;
  obfuscators: string[];
  single_letter_class_ratio?: number;
  total_classes?: number;
  obfuscated_classes_count?: number;
  indicators: JavaObfuscationIndicator[];
  strrat_heuristics?: JavaStrratHeuristics;
}

export interface JavaBehavioralAnalysis {
  internet_activity: JavaInternetActivity;
  file_access: JavaFileAccess;
  command_execution: JavaCommandExecution;
  code_obfuscation: JavaCodeObfuscation;
  strrat_heuristics?: JavaStrratHeuristics;
}








