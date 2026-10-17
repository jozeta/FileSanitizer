import { JobDetail, StructuredMetadata, UrlItem, SanitizationOptions, ValidationComparison, DetectionRules, IncidentCorrelationData, PdfStreamInspection, EnrichIocsResponse } from '../types';
import { APP_VERSION } from '../version';

export interface UpdateCheckResult {
  success: boolean;
  has_update: boolean;
  current_version: string;
  latest_version?: string;
  release_name?: string;
  release_notes?: string;
  published_at?: string;
  html_url?: string;
  source?: string;
  external_blocked?: boolean;
  message?: string;
  error?: string;
  checked_at?: string;
}

const API_BASE = '/api';

export const apiClient = {
  async uploadFiles(
    files: File[],
    onProgress?: (loaded: number, total: number) => void
  ): Promise<{ uploaded: number; jobs: { job_id: string; filename: string; file_size: number; state: string }[] }> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const formData = new FormData();
      for (const f of files) {
        formData.append('files', f);
      }

      if (xhr.upload && onProgress) {
        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) {
            onProgress(e.loaded, e.total);
          }
        });
      }

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const data = JSON.parse(xhr.responseText);
            resolve(data);
          } catch (err) {
            reject(new Error('Invalid response from server'));
          }
        } else {
          try {
            const err = JSON.parse(xhr.responseText);
            reject(new Error(err.detail || 'Upload failed'));
          } catch {
            reject(new Error(`Upload failed with HTTP ${xhr.status}`));
          }
        }
      });

      xhr.addEventListener('error', () => {
        reject(new Error('Network error during file upload'));
      });

      xhr.addEventListener('abort', () => {
        reject(new Error('Upload was aborted'));
      });

      xhr.open('POST', `${API_BASE}/files`);
      xhr.send(formData);
    });
  },

  async fetchUrl(url: string): Promise<{ uploaded: number; jobs: { job_id: string; filename: string; file_size: number; state: string }[]; source_url: string; reputation: any }> {
    const res = await fetch(`${API_BASE}/files/fetch-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'URL fetch failed' }));
      throw new Error(err.detail || 'URL fetch failed');
    }
    return res.json();
  },

  async investigateIoc(ioc: string, iocType?: string, parentJobId?: string): Promise<{ already_analyzed: boolean; job_id: string; filename: string; target: string; message: string }> {
    const res = await fetch(`${API_BASE}/files/investigate-ioc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc, ioc_type: iocType, parent_job_id: parentJobId }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'IOC investigation failed' }));
      throw new Error(err.detail || 'IOC investigation failed');
    }
    return res.json();
  },

  async triggerActiveRecon(jobId: string, authorized: boolean = true): Promise<{ success: boolean; active_recon: any; active_security_probes?: any; risk_scores: any }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/active-recon`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authorized }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Active reconnaissance failed' }));
      throw new Error(err.detail || 'Active reconnaissance failed');
    }
    return res.json();
  },

  async enrichJobIocs(jobId: string, iocs: string[]): Promise<EnrichIocsResponse> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/enrich-iocs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iocs }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to enrich network IOCs' }));
      throw new Error(err.detail || 'Network IOC quick-enrichment failed');
    }
    return res.json();
  },

  async getSupportedFormats(): Promise<{ total_categories: number; categories: any[] }> {
    const res = await fetch(`${API_BASE}/files/supported-formats`);
    if (!res.ok) throw new Error('Failed to fetch supported formats');
    return res.json();
  },

  async getJobStatus(jobId: string): Promise<JobDetail> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}`);
    if (!res.ok) throw new Error('Failed to fetch job status');
    return res.json();
  },

  async getJobAnalysis(jobId: string): Promise<JobDetail> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/analysis`);
    if (!res.ok) throw new Error('Failed to fetch job analysis');
    return res.json();
  },

  async getJobDetectionRules(jobId: string): Promise<DetectionRules> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/detection-rules`);
    if (!res.ok) throw new Error('Failed to fetch detection rules');
    return res.json();
  },

  async getJobMetadata(jobId: string): Promise<StructuredMetadata> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/metadata`);
    if (!res.ok) throw new Error('Failed to fetch job metadata');
    return res.json();
  },

  async getJobUrls(jobId: string): Promise<{ job_id: string; total_urls: number; urls: UrlItem[] }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/urls`);
    if (!res.ok) throw new Error('Failed to fetch job URLs');
    return res.json();
  },

  async getRawContent(jobId: string, offset = 0, length = 150000): Promise<{
    job_id: string;
    filename: string;
    category: string;
    file_size: number;
    offset: number;
    length: number;
    is_truncated: boolean;
    b64: string;
    text: string;
  }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/raw-content?offset=${offset}&length=${length}`);
    if (!res.ok) throw new Error('Failed to fetch raw file content');
    return res.json();
  },

  async getPdfStreamContent(jobId: string, xref: number): Promise<PdfStreamInspection> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/pdf/streams/${xref}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to inspect PDF object stream' }));
      throw new Error(err.detail || 'Failed to inspect PDF object stream');
    }
    return res.json();
  },

  async startSanitization(jobId: string, profile?: string, options?: SanitizationOptions): Promise<any> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/sanitize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile, options }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Sanitization request failed' }));
      throw new Error(err.detail || 'Sanitization request failed');
    }
    return res.json();
  },

  async getJobResult(jobId: string): Promise<{ job_id: string; state: string; is_ready: boolean; sanitized_filename?: string; validation?: ValidationComparison; removed_items: string[]; warnings: string[] }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/result`);
    if (!res.ok) throw new Error('Failed to fetch sanitization result');
    return res.json();
  },

  async unlockJob(jobId: string, password: string): Promise<{ success: boolean; is_unlocked: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to unlock document' }));
      throw new Error(err.detail || 'Failed to unlock document');
    }
    return res.json();
  },

  async reanalyzeJob(jobId: string, overrideExtension?: string, overrideFilename?: string): Promise<{ job_id: string; filename: string; state: string; message: string }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/reanalyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ override_extension: overrideExtension, override_filename: overrideFilename }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Re-analysis request failed' }));
      throw new Error(err.detail || 'Re-analysis request failed');
    }
    return res.json();
  },

  getDownloadUrl(jobId: string): string {
    return `${API_BASE}/jobs/${jobId}/download`;
  },

  getReportUrl(jobId: string, format: 'json' | 'html' = 'html'): string {
    return `${API_BASE}/jobs/${jobId}/report?format=${format}`;
  },

  getForensicReportUrl(jobId: string, format: 'json' | 'html' = 'html'): string {
    return `${API_BASE}/jobs/${jobId}/report?format=${format}`;
  },

  getEmailAttachmentDownloadUrl(jobId: string, attIndex: number): string {
    return `${API_BASE}/jobs/${jobId}/email/attachments/${attIndex}/download`;
  },

  async analyzeEmailAttachment(jobId: string, attIndex: number): Promise<{ success: boolean; job_id: string; filename: string; message: string }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/email/attachments/${attIndex}/analyze`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to queue attachment for analysis' }));
      throw new Error(err.detail || 'Attachment analysis request failed');
    }
    return res.json();
  },

  getBinaryDumpSectionUrl(jobId: string, sectionName: string): string {
    return `${API_BASE}/jobs/${jobId}/binary/dump-section?name=${encodeURIComponent(sectionName)}`;
  },

  getBinaryDumpResourceUrl(jobId: string, resourceType: string, resourceName: string): string {
    return `${API_BASE}/jobs/${jobId}/binary/dump-resource?type=${encodeURIComponent(resourceType)}&name=${encodeURIComponent(resourceName)}`;
  },

  async deleteJob(jobId: string): Promise<void> {
    await fetch(`${API_BASE}/jobs/${jobId}`, { method: 'DELETE' });
  },

  async getHealth(): Promise<any> {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return res.json();
  },

  // Admin Settings & Management API
  async adminLogin(username: string, password: string): Promise<{ success: boolean; token: string; username: string }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    try {
      const res = await fetch(`${API_BASE}/settings/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          username: (username || '').trim(), 
          password: (password || '').trim() 
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!res.ok) {
        let errorDetail = `Login failed (HTTP ${res.status})`;
        try {
          const err = await res.json();
          if (err && err.detail) errorDetail = err.detail;
        } catch {
          if (res.status === 401) {
            errorDetail = 'Invalid administrator username or password.';
          } else if (res.status === 504 || res.status === 502) {
            errorDetail = 'Backend gateway timeout (504). Service is still initializing.';
          }
        }
        throw new Error(errorDetail);
      }
      return res.json();
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new Error('Login connection timed out after 15 seconds. Please ensure the backend is running.');
      }
      throw err;
    }
  },

  async verifyAdminSession(token: string): Promise<boolean> {
    try {
      const res = await fetch(`${API_BASE}/settings/verify`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  async getSettings(token: string): Promise<any> {
    const res = await fetch(`${API_BASE}/settings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) throw new Error('401 Unauthorized');
    if (!res.ok) throw new Error('Failed to load settings');
    return res.json();
  },

  async updateSettings(token: string, payload: any): Promise<any> {
    const res = await fetch(`${API_BASE}/settings`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update settings' }));
      throw new Error(err.detail || 'Failed to update settings');
    }
    return res.json();
  },

  async getUiPreferences(): Promise<{ success: boolean; ui_preferences: { show_telemetry_diagnostics?: boolean; check_for_updates?: boolean } }> {
    try {
      const res = await fetch(`${API_BASE}/settings/ui-preferences`);
      if (!res.ok) return { success: false, ui_preferences: { show_telemetry_diagnostics: false, check_for_updates: true } };
      return res.json();
    } catch {
      return { success: false, ui_preferences: { show_telemetry_diagnostics: false, check_for_updates: true } };
    }
  },

  async checkForUpdates(force = false): Promise<UpdateCheckResult> {
    try {
      const urlParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
      const simVersion = urlParams?.get('simulate_update') || urlParams?.get('simulate_version');
      const params = new URLSearchParams();
      if (force) params.set('force', 'true');
      if (simVersion) params.set('simulate_version', simVersion);
      const qs = params.toString() ? `?${params.toString()}` : '';
      const res = await fetch(`${API_BASE}/settings/check-update${qs}`);
      if (!res.ok) {
        return {
          success: false,
          has_update: false,
          current_version: APP_VERSION,
          error: `HTTP ${res.status}`,
        };
      }
      return res.json();
    } catch (e: any) {
      return {
        success: false,
        has_update: false,
        current_version: APP_VERSION,
        error: e.message || 'Network request failed',
      };
    }
  },

  async updateUiPreferences(token: string, preferences: Record<string, any>): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/ui-preferences`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(preferences),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update UI preferences' }));
      throw new Error(err.detail || 'Failed to update UI preferences');
    }
    return res.json();
  },

  async getClamavStatus(token: string): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/clamav`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to load ClamAV status');
    return res.json();
  },

  async checkClamavUpdates(token: string, force = false): Promise<{ success: boolean; update_check: any }> {
    const res = await fetch(`${API_BASE}/settings/clamav/check-updates?force=${force}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to check ClamAV updates');
    return res.json();
  },

  async updateClamavMirror(token: string): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/clamav/update`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('ClamAV definition update failed');
    return res.json();
  },

  async getClamavUpdateProgress(token: string): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/clamav/update-progress`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to get ClamAV update progress');
    return res.json();
  },

  async uploadClamavDefinitions(token: string, file: File): Promise<any> {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch(`${API_BASE}/settings/clamav/upload-definitions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: fd,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Definition upload failed');
    }
    return res.json();
  },

  uploadClamavDefinitionsWithProgress(
    token: string,
    file: File,
    onProgress: (percent: number, loaded: number, total: number) => void
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/settings/clamav/upload-definitions`);
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          const percent = Math.round((event.loaded / event.total) * 100);
          onProgress(percent, event.loaded, event.total);
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch {
            resolve({ success: true });
          }
        } else {
          try {
            const err = JSON.parse(xhr.responseText);
            reject(new Error(err.detail || 'Upload failed'));
          } catch {
            reject(new Error(`Upload failed with status ${xhr.status}`));
          }
        }
      };

      xhr.onerror = () => reject(new Error('Network error during definition upload'));

      const formData = new FormData();
      formData.append('file', file);
      xhr.send(formData);
    });
  },

  async getYaraRules(token: string): Promise<{ success: boolean; rules: any[] }> {
    const res = await fetch(`${API_BASE}/settings/yara/rules`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to load YARA rules');
    return res.json();
  },

  async addYaraRule(token: string, rule: any): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/yara/rules`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add YARA rule' }));
      throw new Error(err.detail || 'Failed to save YARA rule');
    }
    return res.json();
  },

  async updateYaraRule(token: string, ruleId: string, rule: any): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/yara/rules/${ruleId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update YARA rule' }));
      throw new Error(err.detail || 'Failed to update YARA rule');
    }
    return res.json();
  },

  async validateYaraSyntax(token: string, ruleText: string): Promise<{ valid: boolean; error: string | null }> {
    const res = await fetch(`${API_BASE}/settings/yara/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ rule_text: ruleText }),
    });
    if (!res.ok) throw new Error('Validation failed');
    return res.json();
  },

  async deleteYaraRule(token: string, ruleId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/yara/rules/${ruleId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to delete YARA rule');
    return res.json();
  },

  async toggleYaraRule(token: string, ruleId: string, enabled: boolean): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/yara/rules/${ruleId}/toggle`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) throw new Error('Failed to toggle YARA rule');
    return res.json();
  },

  async getWarningRules(token: string): Promise<{ success: boolean; rules: any[] }> {
    const res = await fetch(`${API_BASE}/settings/warninglist`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to load warning rules');
    return res.json();
  },

  async addWarningRule(token: string, rule: any): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/warninglist`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add rule' }));
      throw new Error(err.detail || 'Failed to add rule');
    }
    return res.json();
  },

  async updateWarningRule(token: string, ruleId: string, rule: any): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/warninglist/${ruleId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update rule' }));
      throw new Error(err.detail || 'Failed to update rule');
    }
    return res.json();
  },

  async deleteWarningRule(token: string, ruleId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/warninglist/${ruleId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to delete rule');
    return res.json();
  },

  async toggleWarningRule(token: string, ruleId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/warninglist/${ruleId}/toggle`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to toggle rule');
    return res.json();
  },

  async getExternalPolicy(token: string): Promise<{ success: boolean; policy: any }> {
    const res = await fetch(`${API_BASE}/settings/external-policy`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) throw new Error('401 Unauthorized');
    if (!res.ok) throw new Error('Failed to load external connection policy');
    return res.json();
  },

  async updateExternalPolicy(token: string, policy: any): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/external-policy`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(policy),
    });
    if (res.status === 401) throw new Error('401 Unauthorized');
    if (!res.ok) throw new Error('Failed to update external policy');
    return res.json();
  },

  async getStatistics(token: string): Promise<{ success: boolean; statistics: any }> {
    const res = await fetch(`${API_BASE}/settings/statistics`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) throw new Error('401 Unauthorized');
    if (!res.ok) throw new Error('Failed to load usage statistics');
    return res.json();
  },

  async getUploadHistory(token: string): Promise<{ success: boolean; history: any[]; enabled: boolean }> {
    const res = await fetch(`${API_BASE}/settings/history`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) throw new Error('401 Unauthorized');
    if (!res.ok) throw new Error('Failed to load upload history');
    return res.json();
  },

  async clearUploadHistory(token: string): Promise<{ success: boolean }> {
    const res = await fetch(`${API_BASE}/settings/history`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) throw new Error('401 Unauthorized');
    if (!res.ok) throw new Error('Failed to clear upload history');
    return res.json();
  },

  async toggleUploadHistory(token: string, enabled: boolean): Promise<{ success: boolean; enabled: boolean }> {
    const res = await fetch(`${API_BASE}/settings/history/toggle`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ enabled }),
    });
    if (res.status === 401) throw new Error('401 Unauthorized');
    if (!res.ok) throw new Error('Failed to toggle upload history');
    return res.json();
  },

  async verifyApiKey(token: string, service: string, apiKey?: string): Promise<{ valid: boolean; service: string; message: string }> {
    const res = await fetch(`${API_BASE}/settings/verify-key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ service, api_key: apiKey }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Verification failed' }));
      throw new Error(err.detail || 'Verification failed');
    }
    return res.json();
  },

  async getDangerousExtensions(token: string): Promise<{ success: boolean; extensions: string[] }> {
    const res = await fetch(`${API_BASE}/settings/dangerous-extensions`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to load dangerous URL extensions');
    return res.json();
  },

  async addDangerousExtension(token: string, extension: string): Promise<{ success: boolean; extensions: string[] }> {
    const res = await fetch(`${API_BASE}/settings/dangerous-extensions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ extension }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add extension' }));
      throw new Error(err.detail || 'Failed to add extension');
    }
    return res.json();
  },

  async deleteDangerousExtension(token: string, extension: string): Promise<{ success: boolean; extensions: string[] }> {
    const res = await fetch(`${API_BASE}/settings/dangerous-extensions/${encodeURIComponent(extension)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to delete dangerous URL extension');
    return res.json();
  },

  async getEmbeddedFiles(jobId: string): Promise<{ job_id: string; total: number; files: any[] }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/embedded-files`);
    if (!res.ok) throw new Error('Failed to fetch embedded files');
    return res.json();
  },

  getEmbeddedFileDownloadUrl(jobId: string, fileId: number): string {
    return `${API_BASE}/jobs/${jobId}/embedded-files/${fileId}/download`;
  },

  async analyzeEmbeddedFile(jobId: string, fileId: number): Promise<{ success: boolean; job_id: string; filename: string; message: string }> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/embedded-files/${fileId}/analyze`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to analyze embedded file' }));
      throw new Error(err.detail || 'Failed to analyze embedded file');
    }
    return res.json();
  },

  async getCustomPatterns(): Promise<{ success: boolean; patterns: any[] }> {
    const res = await fetch(`${API_BASE}/settings/custom-patterns`);
    if (!res.ok) throw new Error('Failed to load custom patterns');
    return res.json();
  },

  async addCustomPattern(token: string, data: { name: string; pattern?: string; type: string; color: string; description?: string; category?: string; offset?: number; length?: number; structure_type?: string; appliesToFormat?: string }): Promise<{ success: boolean; pattern: any }> {
    const res = await fetch(`${API_BASE}/settings/custom-patterns`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add custom pattern' }));
      throw new Error(err.detail || 'Failed to add custom pattern');
    }
    return res.json();
  },

  async updateCustomPattern(token: string, patternId: string, data: { name: string; pattern?: string; type: string; color: string; description?: string; category?: string; offset?: number; length?: number; structure_type?: string; appliesToFormat?: string }): Promise<{ success: boolean; pattern: any }> {
    const res = await fetch(`${API_BASE}/settings/custom-patterns/${encodeURIComponent(patternId)}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update custom pattern' }));
      throw new Error(err.detail || 'Failed to update custom pattern');
    }
    return res.json();
  },

  async deleteCustomPattern(token: string, patternId: string): Promise<{ success: boolean }> {
    const res = await fetch(`${API_BASE}/settings/custom-patterns/${encodeURIComponent(patternId)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to delete custom pattern');
    return res.json();
  },

  async toggleCustomPattern(token: string, patternId: string): Promise<{ success: boolean; enabled: boolean }> {
    const res = await fetch(`${API_BASE}/settings/custom-patterns/${encodeURIComponent(patternId)}/toggle`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to toggle custom pattern');
    return res.json();
  },

  async resetCustomPattern(token: string, patternId: string): Promise<{ success: boolean; pattern: any }> {
    const res = await fetch(`${API_BASE}/settings/custom-patterns/${encodeURIComponent(patternId)}/reset`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to reset custom pattern' }));
      throw new Error(err.detail || 'Failed to reset custom pattern');
    }
    return res.json();
  },

  // File Formats Management
  async getFileFormats(): Promise<{ success: boolean; formats: any[] }> {
    const res = await fetch(`${API_BASE}/settings/file-formats`);
    if (!res.ok) throw new Error('Failed to load file formats');
    return res.json();
  },

  async addFileFormat(token: string, data: { id?: string; name: string; default_extension?: string; extensions?: string[]; magic_bytes?: string; magic_signatures?: string[]; description?: string }): Promise<{ success: boolean; format: any }> {
    const res = await fetch(`${API_BASE}/settings/file-formats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add file format' }));
      throw new Error(err.detail || 'Failed to add file format');
    }
    return res.json();
  },

  async updateFileFormat(token: string, formatId: string, data: { name: string; default_extension?: string; extensions?: string[]; magic_bytes?: string; magic_signatures?: string[]; description?: string }): Promise<{ success: boolean; format: any }> {
    const res = await fetch(`${API_BASE}/settings/file-formats/${encodeURIComponent(formatId)}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update file format' }));
      throw new Error(err.detail || 'Failed to update file format');
    }
    return res.json();
  },

  async deleteFileFormat(token: string, formatId: string): Promise<{ success: boolean }> {
    const res = await fetch(`${API_BASE}/settings/file-formats/${encodeURIComponent(formatId)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to delete file format' }));
      throw new Error(err.detail || 'Failed to delete file format');
    }
    return res.json();
  },

  async toggleFileFormat(token: string, formatId: string): Promise<{ success: boolean; enabled: boolean }> {
    const res = await fetch(`${API_BASE}/settings/file-formats/${encodeURIComponent(formatId)}/toggle`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to toggle file format');
    return res.json();
  },

  // Audit & Debug Logs
  async getAuditLogs(
    token: string,
    params?: { limit?: number; level?: string; search?: string; offset?: number }
  ): Promise<{
    success: boolean;
    total: number;
    counts: { TOTAL: number; DEBUG: number; INFO: number; WARNING: number; ERROR: number; CRITICAL: number };
    current_level: string;
    logs: Array<{
      id: number;
      timestamp: string;
      time_str: string;
      epoch: number;
      level: string;
      logger: string;
      module: string;
      func: string;
      line: number;
      message: string;
      exception?: string;
    }>;
  }> {
    const sp = new URLSearchParams();
    if (params?.limit) sp.append('limit', String(params.limit));
    if (params?.level) sp.append('level', params.level);
    if (params?.search) sp.append('search', params.search);
    if (params?.offset) sp.append('offset', String(params.offset));

    const res = await fetch(`${API_BASE}/settings/logs?${sp.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to fetch audit logs');
    return res.json();
  },

  async clearAuditLogs(token: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/settings/logs`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to clear audit logs');
    return res.json();
  },

  async setLogLevel(token: string, level: string): Promise<{ success: boolean; level: string; message: string }> {
    const res = await fetch(`${API_BASE}/settings/logs/level`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ level }),
    });
    if (!res.ok) throw new Error('Failed to update log level');
    return res.json();
  },

  exportAuditLogsUrl(token: string, format: 'text' | 'json' = 'text'): string {
    return `${API_BASE}/settings/logs/export?format=${format}&token=${encodeURIComponent(token)}`;
  },

  // Archive Auto-Unlocking Pipeline Dictionary
  async getArchivePasswords(): Promise<{ success: boolean; passwords: string[] }> {
    const res = await fetch(`${API_BASE}/settings/archive-passwords`);
    if (!res.ok) throw new Error('Failed to fetch archive passwords');
    return res.json();
  },

  async addArchivePassword(token: string, password: string): Promise<{ success: boolean; passwords: string[] }> {
    const res = await fetch(`${API_BASE}/settings/archive-passwords`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ password }),
    });
    if (!res.ok) throw new Error('Failed to add archive password');
    return res.json();
  },

  async setArchivePasswords(token: string, passwords: string[]): Promise<{ success: boolean; passwords: string[] }> {
    const res = await fetch(`${API_BASE}/settings/archive-passwords`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ passwords }),
    });
    if (!res.ok) throw new Error('Failed to set archive passwords');
    return res.json();
  },

  async deleteArchivePassword(token: string, password: string): Promise<{ success: boolean; passwords: string[] }> {
    const res = await fetch(`${API_BASE}/settings/archive-passwords/${encodeURIComponent(password)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to delete archive password');
    return res.json();
  },

  // Threat Intel & External API Cache Management
  async getCacheStats(token: string): Promise<{ success: boolean; stats: any }> {
    const res = await fetch(`${API_BASE}/settings/cache`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to fetch cache statistics');
    return res.json();
  },

  async getCacheSettings(token?: string): Promise<{ success: boolean; cache_settings: any }> {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API_BASE}/settings/cache/settings`, { headers });
    if (!res.ok) throw new Error('Failed to fetch cache policy settings');
    return res.json();
  },

  async updateCacheSettings(token: string, config: any): Promise<{ success: boolean; cache_settings: any }> {
    const res = await fetch(`${API_BASE}/settings/cache/settings`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(config),
    });
    if (!res.ok) throw new Error('Failed to update cache settings');
    return res.json();
  },

  async clearCache(token: string, namespace?: string): Promise<{ success: boolean; keys_deleted: number; namespace: string }> {
    const url = namespace ? `${API_BASE}/settings/cache/clear?namespace=${encodeURIComponent(namespace)}` : `${API_BASE}/settings/cache/clear`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error('Failed to clear threat intelligence cache');
    return res.json();
  },

  async refreshIntelligence(jobId: string, service: string = 'all', forceRefresh: boolean = true): Promise<{ success: boolean; message?: string; target?: string; domain_info: any }> {
    const res = await fetch(`${API_BASE}/jobs/${encodeURIComponent(jobId)}/refresh-intelligence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service, force_refresh: forceRefresh }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to refresh intelligence data');
    }
    return res.json();
  },

  // Format-Specific CDR & Sanitization Policies
  async getCdrPolicies(): Promise<{ success: boolean; policies: Record<string, any> }> {
    const res = await fetch(`${API_BASE}/settings/cdr-policies`);
    if (!res.ok) throw new Error('Failed to fetch CDR policies');
    return res.json();
  },

  async saveCdrPolicies(token: string, payload: { format_id?: string; policy?: any; policies?: any }): Promise<{ success: boolean; policies: Record<string, any> }> {
    const res = await fetch(`${API_BASE}/settings/cdr-policies`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Failed to save CDR policies');
    return res.json();
  },

  // Multi-Artifact Incident Cross-Correlation & BinDiff
  async correlateJobs(jobIds: string[]): Promise<IncidentCorrelationData> {
    const res = await fetch(`${API_BASE}/jobs/correlate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job_ids: jobIds }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Incident correlation failed' }));
      throw new Error(err.detail || 'Incident correlation failed');
    }
    return res.json();
  },
};


