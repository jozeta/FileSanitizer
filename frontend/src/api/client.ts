import { JobDetail, StructuredMetadata, UrlItem, SanitizationOptions, ValidationComparison } from '../types';

const API_BASE = '/api';

export const apiClient = {
  async uploadFiles(files: File[]): Promise<{ uploaded: number; jobs: { job_id: string; filename: string; file_size: number; state: string }[] }> {
    const formData = new FormData();
    for (const f of files) {
      formData.append('files', f);
    }
    const res = await fetch(`${API_BASE}/files`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
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

  getDownloadUrl(jobId: string): string {
    return `${API_BASE}/jobs/${jobId}/download`;
  },

  getReportUrl(jobId: string): string {
    return `${API_BASE}/jobs/${jobId}/report`;
  },

  async deleteJob(jobId: string): Promise<void> {
    await fetch(`${API_BASE}/jobs/${jobId}`, { method: 'DELETE' });
  },

  async getHealth(): Promise<any> {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return res.json();
  }
};
