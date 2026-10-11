import { JobDetail, WorkspaceJob, IncidentCorrelationData } from '../types';

export interface ClientCrossReference {
  targetJobId: string;
  targetFilename: string;
  targetCategory: string;
  referenceType: string;
  label: string;
  detail: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  matchedBy: 'hash' | 'filename' | 'uri' | 'code' | 'component';
  matchedValue: string;
  eventId?: string;
  computer?: string;
}

// Map of common scenario aliases to help link dropped payloads to root jobs
const KNOWN_SCENARIO_ALIASES: Record<string, string[]> = {
  'beacon_updater.exe': ['03_c2_implant_beacon.exe', 'c2_implant_beacon.exe', 'beacon_updater.exe'],
  'financial_q3_confidential.zip': ['07_exfiltrated_archive.zip', 'exfiltrated_archive.zip', 'financial_q3_confidential.zip'],
  '02_weaponized_document.docm': ['weaponized_document.docm', 'invoice_q3.docm', '02_weaponized_document.docm'],
};

/**
 * Searches workspace jobs to find if a given filename, path, or hash matches an analyzed file.
 */
export function findReferencedJob(
  token: string,
  workspaceJobs: WorkspaceJob[],
  currentJobId?: string
): WorkspaceJob | null {
  if (!token || !workspaceJobs || workspaceJobs.length === 0) return null;
  const clean = token.trim().replace(/^['"\(]+|['"\),;]+$/g, '');
  if (clean.length < 3) return null;

  // Extract base filename from Windows or Unix path
  const basename = clean.replace(/^[a-zA-Z]:\\.*?([^\\]+)$/, '$1').replace(/^.*?([^\/]+)$/, '$1').toLowerCase();
  const cleanLower = clean.toLowerCase();

  for (const job of workspaceJobs) {
    if (currentJobId && job.jobId === currentJobId) continue;

    const jobFn = (job.filename || '').toLowerCase();
    const jobStem = jobFn.replace(/\.[^/.]+$/, '');

    // 0. Direct Job ID match
    if (job.jobId === clean || job.jobId === cleanLower) {
      return job;
    }

    // 0.5. Child job linkage (parent_job_id matches current job)
    if ((job as any).parent_job_id && (job as any).parent_job_id === currentJobId) {
      if (jobFn === basename || jobStem === basename || (job as any).original_filename?.toLowerCase() === basename) {
        return job;
      }
    }

    // 1. Exact or basename match
    if (jobFn === basename || jobStem === basename || jobFn === cleanLower) {
      return job;
    }

    // 2. Hash match
    const hashes = (job as any).hashes || {};
    for (const h of Object.values(hashes)) {
      if (typeof h === 'string' && h.length >= 32) {
        if (cleanLower.includes(h.toLowerCase()) || h.toLowerCase() === cleanLower) {
          return job;
        }
      }
    }

    // 3. Known scenario aliases
    for (const [aliasKey, aliasList] of Object.entries(KNOWN_SCENARIO_ALIASES)) {
      if (aliasKey === basename || aliasList.includes(basename)) {
        if (aliasList.some((a) => jobFn.includes(a.toLowerCase()) || jobStem.includes(a.toLowerCase().replace(/\.[^/.]+$/, '')))) {
          return job;
        }
      }
    }
  }

  return null;
}

/**
 * Detects all cross-artifact references for the current job within the workspace.
 */
export function detectCrossArtifactReferences(
  currentJob: JobDetail | null,
  workspaceJobs: WorkspaceJob[],
  serverCorrelation?: IncidentCorrelationData | null
): ClientCrossReference[] {
  if (!currentJob || !workspaceJobs || workspaceJobs.length <= 1) return [];

  const refsMap = new Map<string, ClientCrossReference>();

  // 1. Incorporate server-side computed references if available
  if (serverCorrelation?.cross_file_references?.by_job) {
    const jobRefs = serverCorrelation.cross_file_references.by_job[currentJob.job_id];
    if (jobRefs) {
      // Outgoing: This file references other files
      (jobRefs.outgoing || []).forEach((r) => {
        const tgtJob = workspaceJobs.find((j) => j.jobId === r.target_job_id);
        const key = `${r.target_job_id}-${r.reference_type}`;
        refsMap.set(key, {
          targetJobId: r.target_job_id,
          targetFilename: tgtJob?.filename || r.target_filename,
          targetCategory: tgtJob?.category || 'file',
          referenceType: r.reference_type,
          label: r.label,
          detail: r.detail,
          confidence: r.confidence,
          matchedBy: r.matched_by,
          matchedValue: r.matched_value,
          eventId: r.event_id,
          computer: r.computer,
        });
      });

      // Incoming: Other files reference this file
      (jobRefs.incoming || []).forEach((r) => {
        const srcJob = workspaceJobs.find((j) => j.jobId === r.source_job_id);
        const key = `in-${r.source_job_id}-${r.reference_type}`;
        refsMap.set(key, {
          targetJobId: r.source_job_id,
          targetFilename: srcJob?.filename || r.source_filename,
          targetCategory: srcJob?.category || 'file',
          referenceType: `REFERENCED_BY_${r.reference_type}`,
          label: `Referenced by ${srcJob?.filename || r.source_filename}`,
          detail: `${srcJob?.filename || r.source_filename} directly references this artifact (${r.label})`,
          confidence: r.confidence,
          matchedBy: r.matched_by,
          matchedValue: r.matched_value,
          eventId: r.event_id,
          computer: r.computer,
        });
      });
    }
  }

  // 2. Client-side Email Attachments Detection
  if (currentJob.email_info?.attachments) {
    currentJob.email_info.attachments.forEach((att) => {
      const match = findReferencedJob(att.filename, workspaceJobs, currentJob.job_id) ||
        (att.sha256 ? findReferencedJob(att.sha256, workspaceJobs, currentJob.job_id) : null);
      if (match) {
        const key = `${match.jobId}-EMAIL_ATTACHMENT`;
        if (!refsMap.has(key)) {
          refsMap.set(key, {
            targetJobId: match.jobId,
            targetFilename: match.filename,
            targetCategory: match.category || 'office',
            referenceType: 'EMAIL_ATTACHMENT',
            label: 'Email Attachment',
            detail: `Email contains embedded attachment '${att.filename}' analyzed in workspace`,
            confidence: 'HIGH',
            matchedBy: att.sha256 ? 'hash' : 'filename',
            matchedValue: att.filename,
          });
        }
      }
    });
  }

  // 3. Client-side PCAP Carved Files & HTTP Transactions Detection
  if (currentJob.pcap_info) {
    const carved = (currentJob.pcap_info as any).carved_files || (currentJob.pcap_info as any).extracted_files || [];
    carved.forEach((cf: any) => {
      const match = findReferencedJob(cf.filename || cf.name || '', workspaceJobs, currentJob.job_id) ||
        (cf.sha256 ? findReferencedJob(cf.sha256, workspaceJobs, currentJob.job_id) : null);
      if (match) {
        const key = `${match.jobId}-CARVED_PAYLOAD`;
        if (!refsMap.has(key)) {
          refsMap.set(key, {
            targetJobId: match.jobId,
            targetFilename: match.filename,
            targetCategory: match.category || 'executable',
            referenceType: 'CARVED_PAYLOAD',
            label: 'Carved Network Payload',
            detail: `Packet capture carved file '${cf.filename}' matching workspace artifact`,
            confidence: 'HIGH',
            matchedBy: cf.sha256 ? 'hash' : 'filename',
            matchedValue: cf.filename || cf.sha256,
          });
        }
      }
    });

    const httpTrans = (currentJob.pcap_info as any).http_transactions || (currentJob.pcap_info as any).http_requests || [];
    httpTrans.forEach((req: any) => {
      const uri = req.uri || req.url || '';
      const match = findReferencedJob(uri, workspaceJobs, currentJob.job_id);
      if (match) {
        const key = `${match.jobId}-NETWORK_DOWNLOAD`;
        if (!refsMap.has(key)) {
          refsMap.set(key, {
            targetJobId: match.jobId,
            targetFilename: match.filename,
            targetCategory: match.category || 'executable',
            referenceType: 'NETWORK_DOWNLOAD',
            label: 'HTTP Transfer Request',
            detail: `HTTP traffic requested transfer of '${match.filename}'`,
            confidence: 'HIGH',
            matchedBy: 'uri',
            matchedValue: uri,
          });
        }
      }
    });
  }

  // 4. Client-side EVTX Process Execution & File Creation Detection
  if (currentJob.evtx_info) {
    const events = (currentJob.evtx_info as any).timeline || currentJob.evtx_info.timeline_events || [];
    events.forEach((ev: any) => {
      const cmd = ev.command_line || ev.details?.CommandLine || '';
      const targetFn = ev.details?.TargetFilename || '';
      const hashes = ev.details?.Hashes || ev.hashes || '';

      const match = findReferencedJob(hashes, workspaceJobs, currentJob.job_id) ||
        findReferencedJob(targetFn, workspaceJobs, currentJob.job_id) ||
        findReferencedJob(cmd, workspaceJobs, currentJob.job_id);

      if (match) {
        const eid = String(ev.event_id || '');
        const key = `${match.jobId}-EVTX_${eid}`;
        if (!refsMap.has(key)) {
          refsMap.set(key, {
            targetJobId: match.jobId,
            targetFilename: match.filename,
            targetCategory: match.category || 'executable',
            referenceType: `EVTX_EVENT_${eid}`,
            label: eid === '11' ? 'File Created on Disk' : eid === '7045' ? 'Service Installed' : 'Process Spawned',
            detail: `Event ${eid} on host ${ev.computer || 'system'} recorded activity for '${match.filename}'`,
            confidence: 'HIGH',
            matchedBy: hashes ? 'hash' : 'filename',
            matchedValue: match.filename,
            eventId: eid,
            computer: ev.computer,
          });
        }
      }
    });
  }

  // 5. Client-side Office Macro Code References
  if (currentJob.office_info?.macro_modules || currentJob.office_info?.macro_details) {
    const code = JSON.stringify(currentJob.office_info.macro_modules || currentJob.office_info.macro_details);
    workspaceJobs.forEach((job) => {
      if (job.jobId === currentJob.job_id) return;
      const match = findReferencedJob(code, [job], currentJob.job_id);
      if (match) {
        const key = `${match.jobId}-MACRO_DROPPER`;
        if (!refsMap.has(key)) {
          refsMap.set(key, {
            targetJobId: match.jobId,
            targetFilename: match.filename,
            targetCategory: match.category || 'executable',
            referenceType: 'MACRO_DROPPER',
            label: 'Macro Download / Dropper Cradle',
            detail: `VBA macro code references payload target '${match.filename}'`,
            confidence: 'HIGH',
            matchedBy: 'code',
            matchedValue: match.filename,
          });
        }
      }
    });
  }

  // 6. Embedded Files (Archives & Documents)
  if (currentJob.embedded_files) {
    currentJob.embedded_files.forEach((emb) => {
      const match = findReferencedJob(emb.name || (emb as any).filename || '', workspaceJobs, currentJob.job_id) ||
        (emb.sha256 ? findReferencedJob(emb.sha256, workspaceJobs, currentJob.job_id) : null);
      if (match) {
        const key = `${match.jobId}-EMBEDDED_ARTIFACT`;
        if (!refsMap.has(key)) {
          refsMap.set(key, {
            targetJobId: match.jobId,
            targetFilename: match.filename,
            targetCategory: match.category || 'archive',
            referenceType: 'EMBEDDED_ARTIFACT',
            label: 'Embedded Artifact Member',
            detail: `Contains embedded member '${emb.name}' matching workspace artifact`,
            confidence: 'HIGH',
            matchedBy: emb.sha256 ? 'hash' : 'filename',
            matchedValue: emb.name || '',
          });
        }
      }
    });
  }

  return Array.from(refsMap.values());
}

/**
 * Splits a text string into token segments, identifying portions that reference workspace jobs.
 */
export function tokenizeReferencedText(
  text: string,
  workspaceJobs: WorkspaceJob[],
  currentJobId?: string
): Array<{ text: string; isMatch: boolean; job?: WorkspaceJob }> {
  if (!text || !workspaceJobs || workspaceJobs.length === 0) {
    return [{ text, isMatch: false }];
  }

  // Collect terms to highlight
  const targetTerms: Array<{ term: string; job: WorkspaceJob }> = [];
  workspaceJobs.forEach((job) => {
    if (currentJobId && job.jobId === currentJobId) return;
    const fn = job.filename || '';
    if (fn.length >= 3) {
      targetTerms.push({ term: fn, job });
      const stem = fn.replace(/\.[^/.]+$/, '');
      if (stem.length >= 4 && stem !== fn) {
        targetTerms.push({ term: stem, job });
      }
    }
    // Check aliases
    for (const [aliasKey, aliasList] of Object.entries(KNOWN_SCENARIO_ALIASES)) {
      if (aliasList.some((a) => fn.toLowerCase().includes(a.toLowerCase()))) {
        targetTerms.push({ term: aliasKey, job });
      }
    }
  });

  if (targetTerms.length === 0) {
    return [{ text, isMatch: false }];
  }

  // Sort terms by length descending to match longest substring first
  targetTerms.sort((a, b) => b.term.length - a.term.length);

  // Build regex pattern matching any of the terms
  const escapedTerms = targetTerms.map((t) => t.term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const regex = new RegExp(`(${escapedTerms})`, 'gi');

  const segments: Array<{ text: string; isMatch: boolean; job?: WorkspaceJob }> = [];
  let lastIdx = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIdx) {
      segments.push({ text: text.slice(lastIdx, match.index), isMatch: false });
    }
    const matchedStr = match[0];
    const matchedTarget = targetTerms.find(
      (t) => t.term.toLowerCase() === matchedStr.toLowerCase()
    );
    segments.push({
      text: matchedStr,
      isMatch: Boolean(matchedTarget),
      job: matchedTarget?.job,
    });
    lastIdx = regex.lastIndex;
  }

  if (lastIdx < text.length) {
    segments.push({ text: text.slice(lastIdx), isMatch: false });
  }

  return segments;
}
