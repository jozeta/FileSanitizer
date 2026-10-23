import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Binary,
  Play,
  Copy,
  Check,
  Download,
  Trash2,
  ArrowDown,
  ArrowUp,
  Search,
  Sparkles,
  Layers,
  ArrowRightLeft,
  ClipboardPaste,
  FileCode,
  AlertCircle,
  Eye,
  EyeOff,
  GripVertical,
  BookmarkPlus,
  Zap,
  ShieldAlert,
  Cpu,
  Globe,
  X
} from 'lucide-react';
import {
  DECODER_OPERATIONS,
  DECODER_PRESETS,
  DecoderOperation,
  RecipeStep,
  executeRecipe,
  getOperationById
} from '../utils/decoderOperations';

interface DecoderViewProps {
  initialInput?: string;
  onClearInitialInput?: () => void;
}

interface SavedRecipe {
  id: string;
  name: string;
  description?: string;
  createdAt: string;
  steps: RecipeStep[];
}

const STORAGE_KEY_SAVED_RECIPES = 'filesanitizer_saved_recipes';

const CATEGORY_META: Record<
  string,
  { label: string; icon: React.FC<{ className?: string }>; color: string; bg: string; border: string }
> = {
  'Encodings': {
    label: 'Data Encodings & Decodings',
    icon: Binary,
    color: 'text-sky-700',
    bg: 'bg-sky-50',
    border: 'border-sky-200'
  },
  'Ciphers': {
    label: 'Ciphers & Cryptography',
    icon: Sparkles,
    color: 'text-purple-700',
    bg: 'bg-purple-50',
    border: 'border-purple-200'
  },
  'Threat Intel': {
    label: 'Threat Intelligence & Defanging',
    icon: ShieldAlert,
    color: 'text-rose-700',
    bg: 'bg-rose-50',
    border: 'border-rose-200'
  },
  'String Utilities': {
    label: 'String Manipulation & Formatting',
    icon: FileCode,
    color: 'text-emerald-700',
    bg: 'bg-emerald-50',
    border: 'border-emerald-200'
  },
  'Hashes': {
    label: 'Cryptographic Hashes & Checksums',
    icon: Cpu,
    color: 'text-amber-700',
    bg: 'bg-amber-50',
    border: 'border-amber-200'
  },
  'Forensics': {
    label: 'Forensic Artifacts & Timestamps',
    icon: Globe,
    color: 'text-indigo-700',
    bg: 'bg-indigo-50',
    border: 'border-indigo-200'
  }
};

const CATEGORY_ORDER: Array<keyof typeof CATEGORY_META> = [
  'Encodings',
  'Ciphers',
  'Threat Intel',
  'String Utilities',
  'Hashes',
  'Forensics'
];

export const DecoderView: React.FC<DecoderViewProps> = ({ initialInput = '', onClearInitialInput }) => {
  // Input & Output State (Clean by default on app load / workbench reset)
  const [input, setInput] = useState<string>('');
  const [output, setOutput] = useState<string>('');
  const [executionTime, setExecutionTime] = useState<number>(0);
  const [errorStepIndex, setErrorStepIndex] = useState<number | undefined>(undefined);
  const [errorMessage, setErrorMessage] = useState<string | undefined>(undefined);

  // Recipe Pipeline State (Clean by default: 0 items in pipeline)
  const [recipe, setRecipe] = useState<RecipeStep[]>([]);
  const [autoBake, setAutoBake] = useState<boolean>(true);
  const [isBaking, setIsBaking] = useState<boolean>(false);

  // Operations Library Search
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Drag and Drop State
  const [isDraggingOverPipeline, setIsDraggingOverPipeline] = useState<boolean>(false);
  const [draggedStepIndex, setDraggedStepIndex] = useState<number | null>(null);
  const [dropTargetIndex, setDropTargetIndex] = useState<number | null>(null);

  // Saved Recipes State (Backed by localStorage)
  const [savedRecipes, setSavedRecipes] = useState<SavedRecipe[]>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY_SAVED_RECIPES);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch {
      // Fallback
    }
    return [];
  });

  // Save Recipe Modal State
  const [isSaveModalOpen, setIsSaveModalOpen] = useState<boolean>(false);
  const [newRecipeName, setNewRecipeName] = useState<string>('');
  const [newRecipeDesc, setNewRecipeDesc] = useState<string>('');
  const [saveToast, setSaveToast] = useState<string | null>(null);

  // Clipboard & UI Toast States
  const [copied, setCopied] = useState<boolean>(false);
  const [pasted, setPasted] = useState<boolean>(false);

  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  // Sync saved recipes with localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY_SAVED_RECIPES, JSON.stringify(savedRecipes));
    } catch (e) {
      console.warn('Failed to save recipes to localStorage', e);
    }
  }, [savedRecipes]);

  // Update input if initialInput prop changes from outside (e.g. from Send to Decoder action)
  useEffect(() => {
    if (initialInput) {
      setInput((prev) => (prev ? `${prev}\n${initialInput}` : initialInput));
      if (onClearInitialInput) {
        onClearInitialInput();
      }
    }
  }, [initialInput, onClearInitialInput]);

  // Execute Recipe
  const bake = async (currentInput: string, currentRecipe: RecipeStep[]) => {
    setIsBaking(true);
    try {
      const res = await executeRecipe(currentInput, currentRecipe);
      setOutput(res.output);
      setExecutionTime(res.executionTimeMs);
      setErrorStepIndex(res.errorStepIndex);
      setErrorMessage(res.errorMessage);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Unexpected execution error');
    } finally {
      setIsBaking(false);
    }
  };

  // Auto-bake on input or recipe changes
  useEffect(() => {
    if (autoBake) {
      const timer = setTimeout(() => {
        bake(input, recipe);
      }, 60);
      return () => clearTimeout(timer);
    }
  }, [input, recipe, autoBake]);

  // Grouped operations list by category
  const groupedOperations = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    const groups: { category: string; operations: DecoderOperation[] }[] = [];

    for (const cat of CATEGORY_ORDER) {
      const ops = DECODER_OPERATIONS.filter((op) => {
        if (op.category !== cat) return false;
        if (!q) return true;
        return (
          op.name.toLowerCase().includes(q) ||
          op.description.toLowerCase().includes(q) ||
          op.category.toLowerCase().includes(q)
        );
      });

      if (ops.length > 0) {
        groups.push({ category: cat, operations: ops });
      }
    }

    return groups;
  }, [searchQuery]);

  // Recipe Step Manipulations
  const handleAddOperation = (op: DecoderOperation, atIndex?: number) => {
    const defaultArgs: Record<string, any> = {};
    op.params.forEach((p) => {
      defaultArgs[p.id] = p.default;
    });

    const newStep: RecipeStep = {
      stepId: `step_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      operationId: op.id,
      args: defaultArgs,
      disabled: false
    };

    setRecipe((prev) => {
      if (typeof atIndex === 'number' && atIndex >= 0 && atIndex <= prev.length) {
        const next = [...prev];
        next.splice(atIndex, 0, newStep);
        return next;
      }
      return [...prev, newStep];
    });
  };

  const handleRemoveStep = (index: number) => {
    setRecipe((prev) => prev.filter((_, i) => i !== index));
  };

  const handleToggleDisableStep = (index: number) => {
    setRecipe((prev) =>
      prev.map((step, i) => (i === index ? { ...step, disabled: !step.disabled } : step))
    );
  };

  const handleMoveStep = (index: number, direction: 'up' | 'down') => {
    setRecipe((prev) => {
      const next = [...prev];
      const targetIndex = direction === 'up' ? index - 1 : index + 1;
      if (targetIndex < 0 || targetIndex >= next.length) return prev;
      const temp = next[index];
      next[index] = next[targetIndex];
      next[targetIndex] = temp;
      return next;
    });
  };

  const handleReorderStep = (sourceIndex: number, targetInsertionIndex: number) => {
    if (sourceIndex === targetInsertionIndex || sourceIndex === targetInsertionIndex - 1) return;
    setRecipe((prev) => {
      const next = [...prev];
      const [moved] = next.splice(sourceIndex, 1);
      const destinationIndex = sourceIndex < targetInsertionIndex ? targetInsertionIndex - 1 : targetInsertionIndex;
      next.splice(destinationIndex, 0, moved);
      return next;
    });
  };

  const handleDropAt = (targetInsertionIndex: number, e: React.DragEvent) => {
    try {
      const jsonStr = e.dataTransfer.getData('application/json');
      if (jsonStr) {
        const parsed = JSON.parse(jsonStr);
        if (parsed.type === 'reorder-step' && typeof parsed.sourceIndex === 'number') {
          handleReorderStep(parsed.sourceIndex, targetInsertionIndex);
          return;
        }
        if (parsed.type === 'new-op' && parsed.operationId) {
          const newOp = getOperationById(parsed.operationId);
          if (newOp) {
            handleAddOperation(newOp, targetInsertionIndex);
            return;
          }
        }
      }
    } catch {}

    if (draggedStepIndex !== null) {
      handleReorderStep(draggedStepIndex, targetInsertionIndex);
      return;
    }

    const raw = e.dataTransfer.getData('text/plain');
    if (raw) {
      const opObj = getOperationById(raw);
      if (opObj) {
        handleAddOperation(opObj, targetInsertionIndex);
      }
    }
  };

  const handleStepArgChange = (stepIndex: number, paramId: string, value: any) => {
    setRecipe((prev) =>
      prev.map((step, i) => {
        if (i !== stepIndex) return step;
        return {
          ...step,
          args: {
            ...step.args,
            [paramId]: value
          }
        };
      })
    );
  };

  const handleClearRecipe = () => {
    setRecipe([]);
    setOutput(input);
  };

  // Quick Apply Preset
  const handleLoadPreset = (presetId: string) => {
    const preset = DECODER_PRESETS.find((p) => p.id === presetId);
    if (!preset) return;
    const newSteps: RecipeStep[] = preset.steps.map((s) => ({
      stepId: `step_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      operationId: s.operationId,
      args: { ...s.args },
      disabled: Boolean(s.disabled)
    }));
    setRecipe(newSteps);
    setSaveToast(`Applied preset: ${preset.name}`);
    setTimeout(() => setSaveToast(null), 2500);
  };

  // Quick Apply Saved Recipe
  const handleApplySavedRecipe = (saved: SavedRecipe) => {
    const newSteps: RecipeStep[] = saved.steps.map((s) => ({
      stepId: `step_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      operationId: s.operationId,
      args: { ...s.args },
      disabled: Boolean(s.disabled)
    }));
    setRecipe(newSteps);
    setSaveToast(`Applied saved recipe: ${saved.name}`);
    setTimeout(() => setSaveToast(null), 2500);
  };

  // Delete Saved Recipe
  const handleDeleteSavedRecipe = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSavedRecipes((prev) => prev.filter((r) => r.id !== id));
  };

  // Save Custom Recipe (Enforcing 2 or more steps)
  const handleOpenSaveModal = () => {
    if (recipe.length < 2) return;
    setNewRecipeName(`Recipe (${recipe.length} ops) - ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`);
    setNewRecipeDesc('');
    setIsSaveModalOpen(true);
  };

  const handleSaveRecipeConfirm = (e: React.FormEvent) => {
    e.preventDefault();
    if (recipe.length < 2) {
      setSaveToast('A recipe must contain 2 or more pipeline operations.');
      setTimeout(() => setSaveToast(null), 3000);
      setIsSaveModalOpen(false);
      return;
    }
    const trimmedName = newRecipeName.trim();
    if (!trimmedName) return;

    const newSaved: SavedRecipe = {
      id: `saved_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      name: trimmedName,
      description: newRecipeDesc.trim() || undefined,
      createdAt: new Date().toISOString(),
      steps: recipe.map((s) => ({
        stepId: s.stepId,
        operationId: s.operationId,
        args: { ...s.args },
        disabled: s.disabled
      }))
    };

    setSavedRecipes((prev) => [newSaved, ...prev]);
    setIsSaveModalOpen(false);
    setSaveToast(`Recipe "${trimmedName}" saved successfully!`);
    setTimeout(() => setSaveToast(null), 3000);
  };

  // Pipe Output to Input
  const handlePipeOutputToInput = () => {
    setInput(output);
  };

  // Copy Output
  const handleCopyOutput = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Paste into Input
  const handlePasteInput = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setInput(text);
      setPasted(true);
      setTimeout(() => setPasted(false), 1500);
    } catch {
      inputRef.current?.focus();
    }
  };

  // Download Output
  const handleDownloadOutput = () => {
    const blob = new Blob([output], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `decoder_output_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Metrics
  const inputCharCount = input.length;
  const inputLineCount = input ? input.split('\n').length : 0;
  const inputByteLength = new TextEncoder().encode(input).length;

  const outputCharCount = output.length;
  const outputByteLength = new TextEncoder().encode(output).length;

  return (
    <div className="max-w-[98rem] mx-auto px-4 py-6 space-y-6">
      {/* Toast Notification */}
      {saveToast && (
        <div className="fixed top-20 right-8 z-50 px-4 py-2.5 bg-slate-900 text-white text-xs font-semibold rounded-2xl shadow-xl flex items-center gap-2 border border-slate-700 animate-in fade-in slide-in-from-top-2 duration-200">
          <Zap className="w-4 h-4 text-amber-400" />
          <span>{saveToast}</span>
        </div>
      )}

      {/* Top Banner / Header */}
      <div className="bg-white border border-slate-200/90 rounded-3xl p-6 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2.5 rounded-2xl bg-indigo-50 border border-indigo-200 text-indigo-700">
              <Binary className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-slate-900">Security Decoder</h2>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Client-side string manipulation, encoding, decoding, threat indicator defanging, and hash calculation.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Apply Bar for Saved Recipes and Research Presets */}
      <div className="bg-white border border-slate-200/90 rounded-3xl p-4 shadow-xs space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-xl bg-indigo-50 border border-indigo-200/80 text-indigo-600">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <span className="text-xs font-bold text-slate-900 uppercase tracking-wider block">Quick Apply Recipes & Presets</span>
              <span className="text-[11px] text-slate-400 font-medium">
                Select a preset or saved multi-step recipe to configure the pipeline
              </span>
            </div>
          </div>

          {/* Quick Apply Dropdown Menu */}
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <select
              value=""
              onChange={(e) => {
                const val = e.target.value;
                if (!val) return;
                if (val.startsWith('preset:')) {
                  handleLoadPreset(val.replace('preset:', ''));
                } else if (val.startsWith('saved:')) {
                  const saved = savedRecipes.find((r) => r.id === val.replace('saved:', ''));
                  if (saved) handleApplySavedRecipe(saved);
                }
              }}
              className="w-full sm:w-80 px-3.5 py-2 text-xs font-semibold text-slate-800 bg-slate-50 border border-slate-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all cursor-pointer shadow-2xs hover:bg-slate-100/80"
            >
              <option value="" disabled>Choose Recipe or Preset to Apply...</option>
              {savedRecipes.length > 0 && (
                <optgroup label="★ Custom Saved Recipes">
                  {savedRecipes.map((r) => (
                    <option key={r.id} value={`saved:${r.id}`}>
                      {r.name} ({r.steps.length} ops)
                    </option>
                  ))}
                </optgroup>
              )}
              <optgroup label="Malware Research">
                {DECODER_PRESETS.filter((p) => p.category === 'Malware Research').map((p) => (
                  <option key={p.id} value={`preset:${p.id}`}>
                    {p.name} ({p.steps.length} steps)
                  </option>
                ))}
              </optgroup>
              <optgroup label="Binary Analysis">
                {DECODER_PRESETS.filter((p) => p.category === 'Binary Analysis').map((p) => (
                  <option key={p.id} value={`preset:${p.id}`}>
                    {p.name} ({p.steps.length} steps)
                  </option>
                ))}
              </optgroup>
              <optgroup label="Vulnerability Research">
                {DECODER_PRESETS.filter((p) => p.category === 'Vulnerability Research').map((p) => (
                  <option key={p.id} value={`preset:${p.id}`}>
                    {p.name} ({p.steps.length} steps)
                  </option>
                ))}
              </optgroup>
              <optgroup label="Threat Intel & Defanging">
                {DECODER_PRESETS.filter((p) => p.category === 'Threat Intel & Defanging').map((p) => (
                  <option key={p.id} value={`preset:${p.id}`}>
                    {p.name} ({p.steps.length} steps)
                  </option>
                ))}
              </optgroup>
            </select>
          </div>
        </div>

        {/* Saved Custom Recipes Row (with delete buttons) if any exist */}
        {savedRecipes.length > 0 && (
          <div className="space-y-1.5 pt-2 border-t border-slate-100">
            <div className="flex items-center gap-1.5 text-xs font-bold text-amber-800">
              <BookmarkPlus className="w-3.5 h-3.5 text-amber-600" />
              <span>Custom Saved Recipes ({savedRecipes.length})</span>
            </div>
            <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
              {savedRecipes.map((saved) => (
                <div
                  key={saved.id}
                  onClick={() => handleApplySavedRecipe(saved)}
                  className="group inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-amber-50/80 hover:bg-amber-100 border border-amber-200 text-amber-900 text-xs font-semibold cursor-pointer transition-all shadow-2xs hover:shadow-xs whitespace-nowrap"
                  title={`${saved.name} (${saved.steps.length} ops)${saved.description ? `\n${saved.description}` : ''}`}
                >
                  <span>{saved.name}</span>
                  <span className="px-1.5 py-0.2 rounded bg-amber-200/80 text-amber-900 text-[10px] font-mono">
                    {saved.steps.length} ops
                  </span>
                  <button
                    onClick={(e) => handleDeleteSavedRecipe(saved.id, e)}
                    className="p-0.5 rounded text-amber-400 hover:text-rose-600 transition-colors cursor-pointer"
                    title="Delete saved recipe"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Main 3-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Column 1: Operations Library (Grouped by Headlines) (3 cols) */}
        <div className="lg:col-span-3 bg-white border border-slate-200/90 rounded-3xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-indigo-600" />
              <span>Operations Library</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              {DECODER_OPERATIONS.length} total
            </span>
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search operations..."
              className="w-full pl-9 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
            />
          </div>

          <p className="text-[11px] text-slate-500 italic">
            Drag any operation to the recipe pipeline or click to append.
          </p>

          {/* Grouped Operations List with Section Headlines */}
          <div className="space-y-5 max-h-[620px] overflow-y-auto pr-1 scrollbar-thin">
            {groupedOperations.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-400 border border-dashed border-slate-200 rounded-2xl">
                No matching operations found.
              </div>
            ) : (
              groupedOperations.map((group) => {
                const meta = CATEGORY_META[group.category] || CATEGORY_META.Encodings;
                const IconComponent = meta.icon;

                return (
                  <div key={group.category} className="space-y-2">
                    {/* Category Headline */}
                    <div className="flex items-center gap-2 px-1 pt-1 pb-1 border-b border-slate-100">
                      <div className={`p-1 rounded-lg ${meta.bg} ${meta.color}`}>
                        <IconComponent className="w-3.5 h-3.5" />
                      </div>
                      <span className="text-xs font-bold text-slate-800 tracking-tight">
                        {meta.label}
                      </span>
                      <span className="ml-auto text-[10px] font-bold px-1.5 py-0.2 rounded-full bg-slate-100 text-slate-500 font-mono">
                        {group.operations.length}
                      </span>
                    </div>

                    {/* Operations within Category */}
                    <div className="space-y-1.5 pl-1">
                      {group.operations.map((op) => (
                        <div
                          key={op.id}
                          draggable
                          onDragStart={(e) => {
                            e.dataTransfer.setData('text/plain', op.id);
                            e.dataTransfer.setData('application/json', JSON.stringify({ type: 'new-op', operationId: op.id }));
                            e.dataTransfer.effectAllowed = 'copy';
                          }}
                          onClick={() => handleAddOperation(op)}
                          className="p-2.5 rounded-xl border border-slate-200 hover:border-indigo-300 hover:bg-indigo-50/40 cursor-grab active:cursor-grabbing transition-all flex items-start justify-between gap-2 group shadow-2xs"
                        >
                          <div className="space-y-0.5 flex-1">
                            <div className="flex items-center gap-1.5">
                              <span className="text-xs font-bold text-slate-900 group-hover:text-indigo-600 transition-colors">
                                {op.name}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed">
                              {op.description}
                            </p>
                          </div>
                          <div
                            className="p-1 text-slate-300 group-hover:text-indigo-500 shrink-0 mt-0.5"
                            title="Drag to pipeline"
                          >
                            <GripVertical className="w-3.5 h-3.5" />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Column 2: Recipe Pipeline (4 cols) */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = draggedStepIndex !== null ? 'move' : 'copy';
            setIsDraggingOverPipeline(true);
          }}
          onDragLeave={(e) => {
            if (!e.currentTarget.contains(e.relatedTarget as Node)) {
              setIsDraggingOverPipeline(false);
              setDropTargetIndex(null);
            }
          }}
          onDrop={(e) => {
            e.preventDefault();
            setIsDraggingOverPipeline(false);
            setDropTargetIndex(null);
            handleDropAt(recipe.length, e);
            setDraggedStepIndex(null);
          }}
          className={`lg:col-span-4 bg-white border rounded-3xl p-5 shadow-xs space-y-4 transition-all ${
            isDraggingOverPipeline
              ? 'border-indigo-400 bg-indigo-50/20 ring-2 ring-indigo-400/20'
              : 'border-slate-200/90'
          }`}
        >
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <div>
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Layers className="w-4 h-4 text-indigo-600" />
                <span>Recipe Pipeline ({recipe.length})</span>
              </h3>
              <p className="text-[11px] text-slate-500">
                Sequential operators executed top-to-bottom.
              </p>
            </div>

            <div className="flex items-center gap-1.5">
              {/* Save Recipe Button (Active only if >= 2 steps) */}
              <button
                onClick={handleOpenSaveModal}
                disabled={recipe.length < 2}
                className="px-2.5 py-1 rounded-xl bg-slate-100 hover:bg-amber-100 border border-slate-200 hover:border-amber-300 disabled:opacity-40 disabled:cursor-not-allowed text-xs font-semibold text-slate-700 hover:text-amber-900 transition-colors flex items-center gap-1 cursor-pointer shadow-2xs"
                title={
                  recipe.length < 2
                    ? 'Recipes require 2 or more pipeline operations to save'
                    : 'Save current pipeline as a reusable recipe'
                }
              >
                <BookmarkPlus className="w-3.5 h-3.5 text-amber-600" />
                <span>Save</span>
              </button>

              {recipe.length > 0 && (
                <button
                  onClick={handleClearRecipe}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                  title="Clear all steps in recipe"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Recipe Controls Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-2xl bg-slate-50 border border-slate-200">
            {/* Presets Dropdown */}
            <select
              onChange={(e) => {
                if (e.target.value) {
                  handleLoadPreset(e.target.value);
                  e.target.value = '';
                }
              }}
              defaultValue=""
              className="text-xs py-1 px-2 rounded-lg bg-white border border-slate-200 text-slate-700 font-medium focus:outline-none cursor-pointer shadow-2xs"
            >
              <option value="" disabled>
                Load Preset Recipe...
              </option>
              {DECODER_PRESETS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.steps.length} ops)
                </option>
              ))}
            </select>

            <div className="flex items-center gap-2">
              {/* Auto-Bake Toggle */}
              <label className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoBake}
                  onChange={(e) => setAutoBake(e.target.checked)}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer w-3.5 h-3.5"
                />
                <span>Auto-Bake</span>
              </label>

              {/* Manual Bake Button */}
              {!autoBake && (
                <button
                  onClick={() => bake(input, recipe)}
                  disabled={isBaking}
                  className="flex items-center gap-1 px-3 py-1 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold shadow-xs cursor-pointer active:scale-95 transition-all"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>Bake</span>
                </button>
              )}
            </div>
          </div>

          {/* Recipe Steps Cards Container */}
          <div className="space-y-2.5 max-h-[520px] overflow-y-auto pr-1 scrollbar-thin">
            {recipe.length === 0 ? (
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  e.dataTransfer.dropEffect = 'copy';
                  setDropTargetIndex(0);
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  handleDropAt(0, e);
                  setDraggedStepIndex(null);
                  setDropTargetIndex(null);
                  setIsDraggingOverPipeline(false);
                }}
                className={`p-8 text-center border-2 border-dashed rounded-2xl space-y-2 transition-all cursor-pointer ${
                  dropTargetIndex === 0
                    ? 'border-indigo-500 bg-indigo-50 text-indigo-800'
                    : 'border-slate-200 text-slate-400'
                }`}
              >
                <FileCode className="w-8 h-8 mx-auto text-slate-300" />
                <p className="text-xs font-semibold text-slate-600">Recipe is empty</p>
                <p className="text-[11px] text-slate-400">
                  Drag operations from the library on the left or click an operation to begin.
                </p>
              </div>
            ) : (
              <>
                {recipe.map((step, idx) => {
                  const op = getOperationById(step.operationId);
                  if (!op) return null;
                  const isErrorStep = errorStepIndex === idx;

                  return (
                    <div key={step.stepId} className="space-y-1.5">
                      {/* Insertion Line Indicator Above Card */}
                      {dropTargetIndex === idx && (
                        <div className="flex items-center gap-1.5 py-1 animate-pulse">
                          <div className="w-2 h-2 rounded-full bg-indigo-600 ring-2 ring-indigo-200" />
                          <div className="h-1 flex-1 bg-indigo-500 rounded-full shadow-xs" />
                          <div className="w-2 h-2 rounded-full bg-indigo-600 ring-2 ring-indigo-200" />
                        </div>
                      )}

                      <div
                        draggable
                        onDragStart={(e) => {
                          setDraggedStepIndex(idx);
                          e.dataTransfer.setData('text/plain', String(idx));
                          e.dataTransfer.setData(
                            'application/json',
                            JSON.stringify({ type: 'reorder-step', sourceIndex: idx })
                          );
                          e.dataTransfer.effectAllowed = 'move';
                        }}
                        onDragEnd={() => {
                          setDraggedStepIndex(null);
                          setDropTargetIndex(null);
                          setIsDraggingOverPipeline(false);
                        }}
                        onDragOver={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          e.dataTransfer.dropEffect = draggedStepIndex !== null ? 'move' : 'copy';
                          const rect = e.currentTarget.getBoundingClientRect();
                          const midY = rect.top + rect.height / 2;
                          const isAfter = e.clientY > midY;
                          const targetIdx = isAfter ? idx + 1 : idx;
                          if (dropTargetIndex !== targetIdx) {
                            setDropTargetIndex(targetIdx);
                          }
                        }}
                        onDrop={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          const rect = e.currentTarget.getBoundingClientRect();
                          const midY = rect.top + rect.height / 2;
                          const isAfter = e.clientY > midY;
                          const targetIdx = isAfter ? idx + 1 : idx;
                          handleDropAt(targetIdx, e);
                          setDraggedStepIndex(null);
                          setDropTargetIndex(null);
                          setIsDraggingOverPipeline(false);
                        }}
                        className={`rounded-2xl border p-3 transition-all ${
                          draggedStepIndex === idx
                            ? 'opacity-40 border-indigo-400 bg-indigo-50/20'
                            : step.disabled
                            ? 'bg-slate-100/60 border-slate-200 opacity-60'
                            : isErrorStep
                            ? 'bg-rose-50/50 border-rose-300'
                            : 'bg-white border-slate-200 shadow-2xs hover:border-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 pb-2 border-b border-slate-100">
                          <div className="flex items-center gap-2">
                            <div
                              className="cursor-grab active:cursor-grabbing text-slate-400 hover:text-slate-600 p-0.5 rounded"
                              title="Drag to reorder step anywhere in the pipeline"
                            >
                              <GripVertical className="w-3.5 h-3.5" />
                            </div>
                            <span className="w-5 h-5 rounded-full bg-slate-900 text-white text-[10px] font-bold flex items-center justify-center font-mono">
                              {idx + 1}
                            </span>
                            <span className="text-xs font-bold text-slate-900">
                              {op.name}
                            </span>
                            {step.disabled && (
                              <span className="text-[9px] font-bold uppercase px-1.5 py-0.2 rounded bg-slate-200 text-slate-600">
                                Bypassed
                              </span>
                            )}
                          </div>

                          {/* Step Controls: Move Up/Down, Disable, Delete */}
                          <div className="flex items-center gap-0.5">
                            <button
                              onClick={() => handleMoveStep(idx, 'up')}
                              disabled={idx === 0}
                              className="p-1 rounded text-slate-400 hover:text-slate-700 disabled:opacity-30 cursor-pointer"
                              title="Move step up"
                            >
                              <ArrowUp className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleMoveStep(idx, 'down')}
                              disabled={idx === recipe.length - 1}
                              className="p-1 rounded text-slate-400 hover:text-slate-700 disabled:opacity-30 cursor-pointer"
                              title="Move step down"
                            >
                              <ArrowDown className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleToggleDisableStep(idx)}
                              className="p-1 rounded text-slate-400 hover:text-indigo-600 cursor-pointer"
                              title={step.disabled ? 'Enable step' : 'Disable (bypass) step'}
                            >
                              {step.disabled ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                            </button>
                            <button
                              onClick={() => handleRemoveStep(idx)}
                              className="p-1 rounded text-slate-400 hover:text-rose-600 hover:bg-rose-50 cursor-pointer"
                              title="Remove step"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>

                        {/* Step Arguments / Form Controls */}
                        {op.params.length > 0 && !step.disabled && (
                          <div className="pt-2.5 space-y-2 text-xs">
                            {op.params.map((param) => {
                              const val = step.args[param.id] !== undefined ? step.args[param.id] : param.default;

                              if (param.type === 'boolean') {
                                return (
                                  <label key={param.id} className="flex items-center gap-2 cursor-pointer select-none">
                                    <input
                                      type="checkbox"
                                      checked={Boolean(val)}
                                      onChange={(e) => handleStepArgChange(idx, param.id, e.target.checked)}
                                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 w-3.5 h-3.5 cursor-pointer"
                                    />
                                    <span className="text-[11px] font-medium text-slate-700">{param.name}</span>
                                  </label>
                                );
                              }

                              if (param.type === 'select') {
                                return (
                                  <div key={param.id} className="flex items-center justify-between gap-2">
                                    <span className="text-[11px] font-medium text-slate-600">{param.name}:</span>
                                    <select
                                      value={val}
                                      onChange={(e) => handleStepArgChange(idx, param.id, e.target.value)}
                                      className="text-xs py-1 px-2 rounded-lg bg-slate-50 border border-slate-200 text-slate-800 font-medium focus:outline-none"
                                    >
                                      {param.options?.map((opt) => (
                                        <option key={opt.value} value={opt.value}>
                                          {opt.label}
                                        </option>
                                      ))}
                                    </select>
                                  </div>
                                );
                              }

                              return (
                                <div key={param.id} className="space-y-1">
                                  <span className="text-[11px] font-medium text-slate-600">{param.name}:</span>
                                  <input
                                    type={param.type === 'number' ? 'number' : 'text'}
                                    value={val}
                                    onChange={(e) =>
                                      handleStepArgChange(
                                        idx,
                                        param.id,
                                        param.type === 'number' ? parseFloat(e.target.value) || 0 : e.target.value
                                      )
                                    }
                                    className="w-full px-2.5 py-1 text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500/20 text-slate-900"
                                  />
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}

                {/* Bottom Drop Zone so user can always drop to the end */}
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    e.dataTransfer.dropEffect = draggedStepIndex !== null ? 'move' : 'copy';
                    if (dropTargetIndex !== recipe.length) {
                      setDropTargetIndex(recipe.length);
                    }
                  }}
                  onDragLeave={(e) => {
                    if (!e.currentTarget.contains(e.relatedTarget as Node)) {
                      if (dropTargetIndex === recipe.length) setDropTargetIndex(null);
                    }
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    handleDropAt(recipe.length, e);
                    setDraggedStepIndex(null);
                    setDropTargetIndex(null);
                    setIsDraggingOverPipeline(false);
                  }}
                  className={`p-3 rounded-2xl border-2 border-dashed transition-all text-center text-xs font-semibold cursor-pointer select-none ${
                    dropTargetIndex === recipe.length
                      ? 'border-indigo-500 bg-indigo-50 text-indigo-700 shadow-sm ring-2 ring-indigo-200'
                      : 'border-slate-200 hover:border-slate-300 text-slate-400 bg-slate-50/50 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5">
                    <ArrowDown className="w-3.5 h-3.5 text-indigo-500" />
                    <span>Drop operation here to place at bottom of pipeline</span>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Column 3: Input & Output Panels (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Input Card */}
          <div className="bg-white border border-slate-200/90 rounded-3xl p-5 shadow-xs space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-slate-900">Input</span>
                <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-500">
                  <span>{inputCharCount} chars</span>
                  <span>•</span>
                  <span>{inputLineCount} lines</span>
                  <span>•</span>
                  <span>{inputByteLength} bytes</span>
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={handlePasteInput}
                  className="px-2.5 py-1 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold flex items-center gap-1 cursor-pointer transition-colors shadow-2xs"
                  title="Paste from clipboard"
                >
                  <ClipboardPaste className="w-3.5 h-3.5" />
                  <span>{pasted ? 'Pasted!' : 'Paste'}</span>
                </button>
                {input && (
                  <button
                    onClick={() => setInput('')}
                    className="p-1 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
                    title="Clear input"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            <textarea
              ref={inputRef}
              data-decoder-input="true"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Paste or type suspicious string, base64 payload, hex stream, or URL to decode..."
              rows={8}
              className="w-full p-3 font-mono text-xs text-slate-900 bg-slate-50 border border-slate-200 rounded-2xl focus:outline-none focus:ring-2 focus:ring-indigo-500/20 resize-y leading-relaxed"
            />
          </div>

          {/* Output Card */}
          <div className="bg-white border border-slate-200/90 rounded-3xl p-5 shadow-xs space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-slate-900">Output</span>
                <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-500">
                  <span>{outputCharCount} chars</span>
                  <span>•</span>
                  <span>{outputByteLength} bytes</span>
                  <span>•</span>
                  <span className="text-indigo-600 font-bold">{executionTime.toFixed(1)}ms</span>
                </div>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={handlePipeOutputToInput}
                  disabled={!output}
                  className="px-2.5 py-1 rounded-xl bg-slate-100 hover:bg-slate-200 disabled:opacity-40 text-slate-700 text-xs font-semibold flex items-center gap-1 cursor-pointer transition-colors shadow-2xs"
                  title="Move output to input for iterative pipeline"
                >
                  <ArrowRightLeft className="w-3.5 h-3.5" />
                  <span>Output ➔ Input</span>
                </button>
                <button
                  onClick={handleCopyOutput}
                  disabled={!output}
                  className="px-2.5 py-1 rounded-xl bg-slate-100 hover:bg-slate-200 disabled:opacity-40 text-slate-700 text-xs font-semibold flex items-center gap-1 cursor-pointer transition-colors shadow-2xs"
                  title="Copy output to clipboard"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>
                <button
                  onClick={handleDownloadOutput}
                  disabled={!output}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 disabled:opacity-40 transition-colors cursor-pointer"
                  title="Download output as .txt file"
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Error Message if Step Failed */}
            {errorMessage && (
              <div className="p-3 bg-rose-50 border border-rose-200 rounded-2xl flex items-start gap-2.5 text-rose-800 text-xs">
                <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="font-bold">Pipeline Error:</span>
                  <p className="font-mono text-[11px] leading-relaxed break-all">{errorMessage}</p>
                </div>
              </div>
            )}

            <textarea
              readOnly
              value={output}
              placeholder="Output of your recipe pipeline appears here..."
              rows={10}
              className="w-full p-3 font-mono text-xs text-slate-900 bg-slate-50 border border-slate-200 rounded-2xl focus:outline-none resize-y leading-relaxed select-all"
            />
          </div>
        </div>
      </div>

      {/* Save Recipe Modal */}
      {isSaveModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-xl bg-amber-50 text-amber-600 border border-amber-200">
                  <BookmarkPlus className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900">Save Custom Recipe</h3>
                  <p className="text-[11px] text-slate-500">
                    Saves this {recipe.length}-step pipeline to quick-apply anytime.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsSaveModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Pipeline Preview */}
            <div className="p-3 rounded-2xl bg-slate-50 border border-slate-200 space-y-1.5">
              <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider">
                Pipeline Steps ({recipe.length} operations):
              </span>
              <div className="flex flex-wrap gap-1.5 pt-0.5">
                {recipe.map((step, i) => {
                  const op = getOperationById(step.operationId);
                  return (
                    <span
                      key={step.stepId}
                      className="px-2 py-0.5 rounded-lg bg-white border border-slate-200 text-[11px] font-semibold text-slate-800 shadow-2xs flex items-center gap-1"
                    >
                      <span className="font-mono text-slate-400">{i + 1}.</span>
                      <span>{op?.name || step.operationId}</span>
                    </span>
                  );
                })}
              </div>
            </div>

            <form onSubmit={handleSaveRecipeConfirm} className="space-y-3 pt-1">
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Recipe Name <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={newRecipeName}
                  onChange={(e) => setNewRecipeName(e.target.value)}
                  placeholder="e.g. Cobalt Strike Dropper Unpack"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Description / Notes (Optional)
                </label>
                <textarea
                  value={newRecipeDesc}
                  onChange={(e) => setNewRecipeDesc(e.target.value)}
                  placeholder="Notes on what payload or malware family this recipe unpacks..."
                  rows={2}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 resize-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsSaveModalOpen(false)}
                  className="px-4 py-2 rounded-xl border border-slate-200 text-xs font-semibold text-slate-600 hover:bg-slate-50 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold shadow-xs cursor-pointer transition-all"
                >
                  Save Recipe
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
