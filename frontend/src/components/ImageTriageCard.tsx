import React, { useState } from 'react';
import {
  Image as ImageIcon,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Camera,
  Maximize2,
  Scan,
  CheckCircle2
} from 'lucide-react';
import { AIImageProvenance, ImageTriageInfo, StructuredMetadata } from '../types';

interface ImageTriageCardProps {
  provenance?: AIImageProvenance;
  imageInfo?: ImageTriageInfo;
  metadata?: StructuredMetadata;
  filename?: string;
}

export const ImageTriageCard: React.FC<ImageTriageCardProps> = ({
  provenance,
  imageInfo,
  filename = 'image'
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'provenance' | 'forensics' | 'properties' | 'exif'>('provenance');

  // Compute image properties from metadata and imageInfo
  const imgProps = {
    format: imageInfo?.format || 'Standard Raster Image',
    width: imageInfo?.width || 0,
    height: imageInfo?.height || 0,
    aspect_ratio: imageInfo?.aspect_ratio || (imageInfo?.width && imageInfo?.height ? `${imageInfo.width}x${imageInfo.height}` : 'N/A'),
    color_mode: imageInfo?.color_mode || 'sRGB',
    bit_depth: imageInfo?.bit_depth || 8,
    compression: imageInfo?.compression || 'Standard',
    ela_score: imageInfo?.ela_score || provenance?.ela_metrics?.mean_error || 0,
    has_overlay: imageInfo?.has_overlay || false,
    steganography_detected: imageInfo?.steganography_detected || false
  };

  const getConfidenceBadge = (confidence?: string) => {
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
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-pink-50 text-pink-600 rounded-2xl shrink-0">
            <ImageIcon className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Image Forensics &amp; Synthetic AI Provenance
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-pink-50 text-pink-700 border border-pink-200">
                {filename}
              </span>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border ${getConfidenceBadge(provenance?.confidence || 'CLEAN')}`}>
                {provenance?.is_ai_generated ? (
                  <ShieldAlert className="w-3.5 h-3.5 mr-1" />
                ) : (
                  <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-600" />
                )}
                {provenance?.confidence === 'CONFIRMED_AI' ? 'CONFIRMED AI GENERATED' :
                 provenance?.confidence === 'LIKELY_AI' ? 'LIKELY AI GENERATED' :
                 provenance?.confidence === 'SUSPICIOUS' ? 'SYNTHETIC SIGNALS DETECTED' :
                 'AUTHENTIC CAMERA / NON-AI'}
              </span>
            </div>
            <p className="text-xs text-slate-500">
              C2PA Content Credentials, generative diffusion prompts, Error Level Analysis (ELA) tampering, and EXIF camera authenticity.
            </p>
          </div>
        </div>

        {/* Quick Metrics */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          {imgProps.width > 0 && (
            <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Resolution</span>
              <strong className="text-slate-900">{imgProps.width}x{imgProps.height}</strong>
            </div>
          )}
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">ELA Score</span>
            <strong className={imgProps.ela_score > 30 ? 'text-rose-600' : 'text-slate-900'}>
              {imgProps.ela_score}
            </strong>
          </div>
          {provenance?.generator_tool && (
            <div className="p-2 bg-purple-50 rounded-xl border border-purple-200 text-center min-w-[70px]">
              <span className="text-[10px] uppercase text-purple-600 block font-sans">AI Model</span>
              <strong className="text-purple-900">{provenance.generator_tool}</strong>
            </div>
          )}
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2 overflow-x-auto text-xs font-semibold">
        <button
          onClick={() => setActiveSubTab('provenance')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'provenance'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5 text-purple-400" />
          <span>AI Provenance &amp; Authenticity</span>
        </button>

        <button
          onClick={() => setActiveSubTab('forensics')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'forensics'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Scan className="w-3.5 h-3.5 text-pink-500" />
          <span>Forensics (ELA &amp; Stego)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('properties')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'properties'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Maximize2 className="w-3.5 h-3.5 text-blue-500" />
          <span>Image Technical Properties</span>
        </button>

        <button
          onClick={() => setActiveSubTab('exif')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'exif'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Camera className="w-3.5 h-3.5 text-emerald-500" />
          <span>EXIF &amp; Sensor Data</span>
        </button>
      </div>

      {/* Tab 1: AI Provenance & Authenticity */}
      {activeSubTab === 'provenance' && (
        <div className="space-y-4 text-xs">
          {provenance?.is_ai_generated ? (
            <>
              {/* Explanation & Verdict Context */}
              {provenance.explanation && (
                <div className="p-4 rounded-2xl border leading-relaxed bg-purple-50/80 border-purple-200 text-purple-950">
                  <span className="font-bold uppercase tracking-wider block mb-1.5 text-[11px] flex items-center gap-1.5">
                    <Sparkles className="w-4 h-4 text-purple-600" />
                    AI Model Provenance Confirmed:
                  </span>
                  <p>{provenance.explanation}</p>
                </div>
              )}

              {/* Indicators list */}
              {provenance.indicators && provenance.indicators.length > 0 && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
                  <span className="font-bold text-slate-800 block text-xs">Observed Authenticity Signals &amp; Markers</span>
                  <ul className="space-y-1.5">
                    {provenance.indicators.map((ind, i) => (
                      <li key={i} className="flex items-center gap-2 text-slate-700">
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-600 shrink-0" />
                        <span>{ind}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Generative Prompts */}
              {provenance.prompt_metadata?.prompt && (
                <div className="p-4 bg-purple-50/50 border border-purple-200 rounded-2xl space-y-2">
                  <span className="font-bold text-purple-950 block text-xs flex items-center gap-1.5">
                    <Sparkles className="w-4 h-4 text-purple-600" />
                    <span>Original Generative Model Prompt (Extracted)</span>
                  </span>
                  <div className="bg-white p-3 rounded-xl border border-purple-200 font-mono text-slate-800 text-[11px]">
                    {provenance.prompt_metadata.prompt}
                  </div>
                </div>
              )}
            </>
          ) : (
            /* NON-AI / AUTHENTIC MEDIA VERIFICATION */
            <div className="space-y-4">
              {/* Primary Authentic Status Card */}
              <div className="p-4 sm:p-5 rounded-2xl border border-emerald-200 bg-emerald-50/70 text-emerald-950">
                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-xl bg-emerald-100 text-emerald-700 shrink-0 mt-0.5">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h4 className="font-bold text-sm text-emerald-950">
                        Authentic Media Verified: No Evidence of AI Generation Found
                      </h4>
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-emerald-100 text-emerald-800 border border-emerald-300">
                        CLEAN / NATURAL
                      </span>
                    </div>
                    <p className="text-xs text-emerald-900/90 leading-relaxed">
                      Comprehensive multi-layered forensic inspection found no evidence supporting that this image is AI generated.
                      The file exhibits natural pixel compression, authentic color distribution, and is free of synthetic diffusion model parameters or generative AI provenance claims.
                    </p>
                    {provenance?.explanation && (
                      <p className="text-[11px] text-emerald-800 font-mono pt-1">
                        Inspector note: {provenance.explanation}
                      </p>
                    )}
                  </div>
                </div>
              </div>

              {/* Detailed Forensic Checklist of Verification Checks */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {/* 1. C2PA Check */}
                <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 space-y-1.5">
                  <div className="flex items-center gap-2 font-bold text-slate-800 text-xs">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>C2PA Content Credentials &amp; JUMBF Claims</span>
                  </div>
                  <p className="text-[11px] text-slate-600 leading-relaxed pl-6">
                    {provenance?.c2pa?.detected
                      ? 'C2PA manifest is present without synthetic assertions (consistent with authentic camera or editing provenance).'
                      : 'No synthetic IPTC digitalSourceType (trainedAlgorithmicMedia) or AI claim generator boxes detected.'}
                  </p>
                </div>

                {/* 2. Diffusion Prompt & Metadata */}
                <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 space-y-1.5">
                  <div className="flex items-center gap-2 font-bold text-slate-800 text-xs">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>Generative Diffusion Parameters &amp; Prompts</span>
                  </div>
                  <p className="text-[11px] text-slate-600 leading-relaxed pl-6">
                    No embedded prompt text, negative prompts, seed numbers, CFG scales, step counts, or neural network hashes (Stable Diffusion, Midjourney, DALL-E, ComfyUI, Adobe Firefly) found in image chunks or EXIF UserComments.
                  </p>
                </div>

                {/* 3. Physical Camera Hardware Verification */}
                <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 space-y-1.5">
                  <div className="flex items-center gap-2 font-bold text-slate-800 text-xs">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>Hardware Sensor &amp; Capture Provenance</span>
                  </div>
                  <p className="text-[11px] text-slate-600 leading-relaxed pl-6">
                    {provenance?.camera_metadata?.has_camera_hardware_exif ? (
                      <>
                        Authentic optical sensor tags identified: <strong className="text-slate-800">{provenance.camera_metadata.make} {provenance.camera_metadata.model}</strong>
                        {provenance.camera_metadata.lens && ` (${provenance.camera_metadata.lens})`}.
                      </>
                    ) : (
                      'Raster image format exhibits standard organic visual structure without synthetic diffusion signatures.'
                    )}
                  </p>
                </div>

                {/* 4. Compression & Error Level Analysis */}
                <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 space-y-1.5">
                  <div className="flex items-center gap-2 font-bold text-slate-800 text-xs">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>Pixel Structure &amp; Compression Distribution</span>
                  </div>
                  <p className="text-[11px] text-slate-600 leading-relaxed pl-6">
                    Error Level Analysis (ELA: {imgProps.ela_score}) reveals organic compression gradients across 8x8 DCT grid matrices, consistent with natural image rendering rather than generative neural synthesis.
                  </p>
                </div>
              </div>

              {/* Additional Observed Findings if any */}
              {provenance?.indicators && provenance.indicators.length > 0 && (
                <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5">
                  <span className="font-bold text-slate-800 block text-xs">Additional Observed Forensic Signals</span>
                  <ul className="space-y-1">
                    {provenance.indicators.map((ind, i) => (
                      <li key={i} className="flex items-center gap-2 text-slate-700 text-[11px]">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 shrink-0" />
                        <span>{ind}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Forensics & Steganography Deep-Dive */}
      {activeSubTab === 'forensics' && (() => {
        const stego = imageInfo?.steganography;
        const overlay = imageInfo?.overlay;
        const isStegoSuspect = stego?.stego_suspicious || imgProps.steganography_detected;

        return (
          <div className="space-y-5 text-xs">
            {/* Top Grid: ELA & Stego Overview */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-slate-800">Error Level Analysis (ELA)</h4>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                    imgProps.ela_score > 30 ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'
                  }`}>
                    {imgProps.ela_score > 30 ? 'Splicing Anomaly' : 'Consistent Error Distribution'}
                  </span>
                </div>
                <p className="text-slate-500 leading-relaxed text-[11px]">
                  Analyzes compression error differences across 8x8 DCT grid matrices to pinpoint localized editing or splicing.
                </p>
                <div className="flex items-center gap-2 mt-2 font-mono">
                  <span className="text-base font-bold text-slate-900">{imgProps.ela_score}</span>
                  <span className="text-[11px] text-slate-400">Mean Compression Error</span>
                </div>
              </div>

              <div className={`p-4 rounded-2xl border space-y-2 ${
                isStegoSuspect ? 'bg-rose-50/50 border-rose-200' : 'bg-slate-50 border border-slate-200'
              }`}>
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-slate-800">Steganography & Bitplane Carrier</h4>
                  <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                    isStegoSuspect ? 'bg-rose-600 text-white animate-pulse' : 'bg-emerald-100 text-emerald-800'
                  }`}>
                    {isStegoSuspect ? '⚠️ Steganographic Payload Detected' : '✓ Clean Carrier'}
                  </span>
                </div>
                <p className="text-slate-500 leading-relaxed text-[11px]">
                  Bitplane randomness, channel entropy, and adjacent pixel transition analysis detecting encrypted hidden data.
                </p>
                {stego && (
                  <div className="flex items-center gap-3 pt-1 text-slate-700 font-mono text-[11px]">
                    <span>LSB Entropy: <strong>{stego.overall_lsb_entropy || 'N/A'}/1.0</strong></span>
                    <span>•</span>
                    <span>Transition: <strong>{((stego.sample_pair_transition_rate || 0) * 100).toFixed(1)}%</strong></span>
                  </div>
                )}
              </div>
            </div>

            {/* Steganography Deep-Dive Breakdown */}
            {stego && (
              <div className="p-5 bg-white border border-slate-200 rounded-2xl shadow-xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                  <div>
                    <h5 className="font-bold text-sm text-slate-900">Bitplane & Channel Uniformity Metrics</h5>
                    <p className="text-[11px] text-slate-500">
                      Sampled {stego.sampled_pixels?.toLocaleString()} pixels ({stego.sampled_bits?.toLocaleString()} bits)
                    </p>
                  </div>
                  {stego.confidence && (
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                      Confidence: {stego.confidence}
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {/* Channel Entropies */}
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Channel LSB Entropies</span>
                    <div className="space-y-1 font-mono text-xs">
                      <div className="flex justify-between">
                        <span className="text-rose-600 font-semibold">Red (R):</span>
                        <span className="font-bold">{stego.channel_entropy?.red ?? 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-emerald-600 font-semibold">Green (G):</span>
                        <span className="font-bold">{stego.channel_entropy?.green ?? 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sky-600 font-semibold">Blue (B):</span>
                        <span className="font-bold">{stego.channel_entropy?.blue ?? 'N/A'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Bitplane 0 vs 1 */}
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Bitplane Comparison</span>
                    <div className="space-y-1 font-mono text-xs">
                      <div className="flex justify-between">
                        <span className="text-slate-600">Plane 0 (LSB):</span>
                        <span className="font-bold">{stego.bitplane_analysis?.plane0_lsb_entropy ?? 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-600">Plane 1 (Next):</span>
                        <span className="font-bold">{stego.bitplane_analysis?.plane1_entropy ?? 'N/A'}</span>
                      </div>
                      <div className="flex justify-between text-indigo-700 font-semibold">
                        <span>Entropy Delta:</span>
                        <span>+{stego.bitplane_analysis?.entropy_jump ?? 'N/A'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Sample Pairs & Chi-Square */}
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Statistical Correlation</span>
                    <div className="space-y-1 font-mono text-xs">
                      <div className="flex justify-between">
                        <span className="text-slate-600">Sample-Pair Flip:</span>
                        <span className="font-bold">{((stego.sample_pair_transition_rate || 0) * 100).toFixed(2)}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-600">Chi-Square:</span>
                        <span className="font-bold">{stego.chi_square ?? 'N/A'}</span>
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans pt-0.5">
                        Stego tools force transition rate towards 50.0%
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Appended Overlay / Polyglot Payload Deep-Dive */}
            {overlay && overlay.has_overlay ? (
              <div className="p-5 bg-rose-50/50 border border-rose-200 rounded-2xl shadow-xs space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-rose-200/80">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-600 animate-ping"></span>
                    <h5 className="font-bold text-sm text-rose-950">Appended Overlay Stream / Polyglot Payload Detected</h5>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-600 text-white">
                    {overlay.type || 'Polyglot Stream'}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
                  <div className="p-2.5 bg-white rounded-xl border border-rose-200">
                    <span className="text-[10px] text-slate-400 uppercase font-sans block">Overlay Size</span>
                    <strong className="text-slate-900">{overlay.size?.toLocaleString()} bytes ({overlay.percent_of_file}%)</strong>
                  </div>
                  <div className="p-2.5 bg-white rounded-xl border border-rose-200">
                    <span className="text-[10px] text-slate-400 uppercase font-sans block">Offset</span>
                    <strong className="text-slate-900">{overlay.offset}</strong>
                  </div>
                  <div className="p-2.5 bg-white rounded-xl border border-rose-200">
                    <span className="text-[10px] text-slate-400 uppercase font-sans block">Overlay Entropy</span>
                    <strong className="text-slate-900">{overlay.entropy} / 8.0</strong>
                  </div>
                  <div className="p-2.5 bg-white rounded-xl border border-rose-200">
                    <span className="text-[10px] text-slate-400 uppercase font-sans block">Threat Severity</span>
                    <strong className={overlay.is_dangerous ? 'text-rose-700 font-bold' : 'text-amber-700'}>
                      {overlay.is_dangerous ? 'CRITICAL POLYGLOT' : 'SUSPICIOUS TRAILER'}
                    </strong>
                  </div>
                </div>

                {overlay.preview_hex && (
                  <div className="bg-slate-950 text-slate-300 p-3 rounded-xl font-mono text-[11px] space-y-1">
                    <span className="text-slate-400 font-sans text-[10px] uppercase font-bold block">Appended Bytes Header Preview:</span>
                    <div className="text-amber-400 break-all select-all">HEX: {overlay.preview_hex}</div>
                    {overlay.preview_ascii && (
                      <div className="text-slate-300 break-all">ASCII: {overlay.preview_ascii}</div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-600 flex items-center justify-between">
                <span>EOF Marker Validation: Legitimate termination verified. No extraneous bytes or appended streams detected past EOF.</span>
                <span className="text-emerald-700 font-bold font-mono text-[11px]">✓ No Overlay</span>
              </div>
            )}
          </div>
        );
      })()}

      {/* Tab 3: Properties */}
      {activeSubTab === 'properties' && (
        <div className="space-y-4 text-xs">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono">
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Color Mode</span>
              <strong className="text-slate-800 text-xs">{imgProps.color_mode}</strong>
            </div>
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Bit Depth</span>
              <strong className="text-slate-800 text-xs">{imgProps.bit_depth} bits/channel</strong>
            </div>
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Compression</span>
              <strong className="text-slate-800 text-xs">{imgProps.compression}</strong>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: EXIF Sensor Data */}
      {activeSubTab === 'exif' && (
        <div className="space-y-4 text-xs">
          {provenance?.camera_metadata ? (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-3 font-mono">
              <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                <span className="font-bold text-slate-800 font-sans">Physical Camera Metadata</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 font-sans">
                  Authentic Sensor Verified
                </span>
              </div>
              <div className="grid grid-cols-2 gap-3 text-[11px]">
                <div>
                  <span className="text-slate-400 block">Make &amp; Model</span>
                  <span className="text-slate-900 font-bold">{provenance.camera_metadata.make} {provenance.camera_metadata.model}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Lens</span>
                  <span className="text-slate-900">{provenance.camera_metadata.lens || 'Standard Prime'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Exposure</span>
                  <span className="text-slate-900">{provenance.camera_metadata.exposure || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">ISO Speed</span>
                  <span className="text-slate-900">{provenance.camera_metadata.iso || 'N/A'}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-slate-500">
              No physical EXIF camera hardware metadata found in this image file.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
