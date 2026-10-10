import React from 'react';
import { AIImageProvenance } from '../types';
import {
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Camera,
  Cpu,
  FileCheck
} from 'lucide-react';

interface AIImageProvenanceCardProps {
  provenance: AIImageProvenance;
}

export const AIImageProvenanceCard: React.FC<AIImageProvenanceCardProps> = ({ provenance }) => {
  const {
    is_ai_generated,
    confidence,
    generator_tool,
    c2pa,
    prompt_metadata,
    camera_metadata,
    ela_metrics,
    indicators
  } = provenance;

  const getConfidenceBadge = () => {
    switch (confidence) {
      case 'CONFIRMED_AI':
        return 'bg-purple-100 text-purple-800 border-purple-300';
      case 'LIKELY_AI':
        return 'bg-pink-100 text-pink-800 border-pink-300';
      case 'SUSPICIOUS':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      default:
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden mb-6">
      {/* Header */}
      <div className="px-6 py-4 bg-gradient-to-r from-purple-50/80 via-slate-50 to-white border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-purple-100/70 text-purple-700 rounded-lg">
            <Sparkles className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-slate-800">
                AI Image Verification &amp; Provenance
              </h3>
              {c2pa?.detected && (
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-blue-100 text-blue-800 border border-blue-200">
                  C2PA Provenance
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              OpenAI Verify &amp; C2PA Content Credentials inspection (Coalition for Content Provenance and Authenticity)
            </p>
          </div>
        </div>

        {/* Verdict Badge */}
        <div className="flex items-center gap-2">
          <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold border ${getConfidenceBadge()}`}>
            {is_ai_generated ? (
              <ShieldAlert className="w-4 h-4 mr-1.5" />
            ) : (
              <ShieldCheck className="w-4 h-4 mr-1.5 text-emerald-600" />
            )}
            {confidence === 'CONFIRMED_AI' ? 'CONFIRMED AI GENERATED' :
             confidence === 'LIKELY_AI' ? 'LIKELY AI GENERATED' :
             confidence === 'SUSPICIOUS' ? 'SYNTHETIC SIGNALS DETECTED' :
             'AUTHENTIC CAMERA / NON-AI'}
          </span>
        </div>
      </div>

      <div className="p-6 space-y-6 text-xs">
        {/* Explanation & Verdict Context */}
        {provenance.explanation && (
          <div className={`p-4 rounded-xl border ${
            is_ai_generated
              ? 'bg-purple-50/80 border-purple-200 text-purple-950'
              : confidence === 'SUSPICIOUS'
              ? 'bg-amber-50/90 border-amber-300 text-amber-950'
              : 'bg-emerald-50/80 border-emerald-200 text-emerald-950'
          }`}>
            <span className="font-bold uppercase tracking-wider block mb-1 text-[11px] flex items-center gap-1.5">
              {confidence === 'SUSPICIOUS' ? (
                <>
                  <ShieldAlert className="w-4 h-4 text-amber-600" />
                  Signal Analysis &amp; Explanation:
                </>
              ) : is_ai_generated ? (
                <>
                  <Sparkles className="w-4 h-4 text-purple-600" />
                  Provenance Confirmation:
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4 text-emerald-600" />
                  Image Authenticity Verdict:
                </>
              )}
            </span>
            <p className="text-xs leading-relaxed font-medium">
              {provenance.explanation}
            </p>
            {confidence === 'SUSPICIOUS' && (
              <div className="mt-2.5 pt-2 border-t border-amber-200/80 text-[11px] text-amber-800">
                <span className="font-semibold">Why this may be a false positive: </span>
                Screenshots, vector illustrations, graphics, or conventional photos that were re-saved or downloaded from social media/messaging apps naturally lack camera hardware EXIF tags and may feature uniform compression profiles. Review C2PA and prompt sections below for definitive confirmation.
              </div>
            )}
          </div>
        )}

        {/* Indicators or Authentic Verification Banner */}
        {indicators && indicators.length > 0 ? (
          <div className={`p-4 rounded-xl border ${
            is_ai_generated ? 'bg-purple-50/80 border-purple-200 text-purple-950' : 'bg-slate-50 border-slate-200 text-slate-800'
          }`}>
            <span className="font-bold uppercase tracking-wider block mb-1 text-[11px]">
              Key Provenance Findings:
            </span>
            <ul className="space-y-1 list-disc list-inside">
              {indicators.map((ind, i) => (
                <li key={i} className="font-medium">{ind}</li>
              ))}
            </ul>
          </div>
        ) : !is_ai_generated ? (
          <div className="p-4 rounded-xl border bg-emerald-50/70 border-emerald-200 text-emerald-950 space-y-2">
            <span className="font-bold uppercase tracking-wider block text-[11px] flex items-center gap-1.5 text-emerald-800">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              Authentic Media Verification — No AI Signatures Detected
            </span>
            <p className="text-xs text-emerald-900 leading-relaxed font-medium">
              Multi-layered forensic verification found no evidence that supports that this image is AI generated.
              Inspection confirmed absence of C2PA synthetic media assertions (trainedAlgorithmicMedia), no diffusion model prompts or seed parameters, and natural optical sensor/pixel characteristics.
            </p>
          </div>
        ) : null}

        {/* Grid: C2PA & Diffusion Parameters */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* C2PA Manifest Store */}
          <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50">
            <h4 className="font-bold text-slate-800 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <FileCheck className="w-4 h-4 text-blue-600" />
              C2PA Manifest &amp; Claim Credentials
            </h4>

            <div className="space-y-2.5">
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Manifest Detected:</span>
                <span className="font-semibold text-slate-800">
                  {c2pa?.detected ? 'Yes (JUMBF C2PA Box Present)' : 'No C2PA Manifest'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Claim Generator:</span>
                <span className="font-semibold text-purple-700">
                  {c2pa?.claim_generator || generator_tool || 'None / Not Claimed'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">digitalSourceType:</span>
                <span className="font-mono text-slate-700">
                  {c2pa?.is_algorithmic_media ? 'trainedAlgorithmicMedia (IPTC AI)' : 'None'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Actions Recorded:</span>
                <span className="font-mono text-slate-800">
                  {c2pa?.actions && c2pa.actions.length > 0 ? c2pa.actions.join(', ') : 'N/A'}
                </span>
              </div>
            </div>
          </div>

          {/* Camera Hardware Metadata */}
          <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50">
            <h4 className="font-bold text-slate-800 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Camera className="w-4 h-4 text-emerald-600" />
              Physical Camera Hardware Verification
            </h4>

            <div className="space-y-2.5">
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Camera Hardware EXIF:</span>
                <span className={`font-semibold ${camera_metadata?.has_camera_hardware_exif ? 'text-emerald-700' : 'text-slate-500'}`}>
                  {camera_metadata?.has_camera_hardware_exif ? 'Authentic Camera Tags Present' : 'Absent (Synthetic / Software)'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Make &amp; Model:</span>
                <span className="font-medium text-slate-800">
                  {camera_metadata?.make || camera_metadata?.model ? `${camera_metadata?.make || ''} ${camera_metadata?.model || ''}`.trim() : 'N/A'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Lens Model:</span>
                <span className="text-slate-700">{camera_metadata?.lens || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Error Level Analysis (ELA):</span>
                <span className="font-mono text-slate-800">
                  {ela_metrics?.performed ? `Mean: ${ela_metrics.mean_error}, Noise: ${ela_metrics.noise_uniformity}` : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Embedded Model Prompt & Generation Parameters */}
        {prompt_metadata?.detected && (
          <div className="border border-purple-200 rounded-xl p-4 bg-purple-50/40 space-y-3">
            <h4 className="font-bold text-purple-950 uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-purple-700" />
              Embedded AI Generation Prompt &amp; Model Parameters ({prompt_metadata.tool})
            </h4>

            {prompt_metadata.prompt && (
              <div>
                <span className="font-semibold text-slate-700 block mb-1">Prompt:</span>
                <p className="bg-white p-2.5 rounded border border-purple-200 text-slate-800 font-mono text-[11px] whitespace-pre-wrap">
                  {prompt_metadata.prompt}
                </p>
              </div>
            )}

            {prompt_metadata.negative_prompt && (
              <div>
                <span className="font-semibold text-slate-700 block mb-1">Negative Prompt:</span>
                <p className="bg-white p-2.5 rounded border border-purple-200 text-slate-700 font-mono text-[11px] whitespace-pre-wrap">
                  {prompt_metadata.negative_prompt}
                </p>
              </div>
            )}

            {prompt_metadata.parameters && Object.keys(prompt_metadata.parameters).length > 0 && (
              <div>
                <span className="font-semibold text-slate-700 block mb-1.5">Model Parameters:</span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {Object.entries(prompt_metadata.parameters).map(([key, val]) => (
                    <div key={key} className="bg-white p-2 rounded border border-purple-200">
                      <span className="text-[10px] text-slate-400 font-semibold block uppercase">{key}</span>
                      <span className="font-mono font-bold text-purple-950">{val}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
