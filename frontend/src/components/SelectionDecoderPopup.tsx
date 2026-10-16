import React, { useState, useEffect, useRef } from 'react';
import { Binary, ArrowRight } from 'lucide-react';

interface SelectionDecoderPopupProps {
  onSendToDecoder?: (text: string) => void;
}

export const SelectionDecoderPopup: React.FC<SelectionDecoderPopupProps> = ({ onSendToDecoder }) => {
  const [visible, setVisible] = useState<boolean>(false);
  const [position, setPosition] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [selectedText, setSelectedText] = useState<string>('');
  const popupRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let timeoutId: any = null;

    const handleSelectionChange = () => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        const selection = window.getSelection();
        if (!selection || selection.isCollapsed) {
          setVisible(false);
          return;
        }

        const text = selection.toString().trim();
        if (!text || text.length === 0) {
          setVisible(false);
          return;
        }

        // Avoid showing if user is selecting inside the decoder input itself
        const anchorNode = selection.anchorNode;
        if (anchorNode && anchorNode.parentElement?.closest('[data-decoder-input="true"]')) {
          setVisible(false);
          return;
        }

        try {
          const range = selection.getRangeAt(0);
          const rect = range.getBoundingClientRect();
          if (rect.width === 0 && rect.height === 0) {
            setVisible(false);
            return;
          }

          // Calculate ideal coordinates centered above the selection
          const popupWidth = 160;
          const popupHeight = 38;
          let x = rect.left + rect.width / 2 - popupWidth / 2;
          let y = rect.top - popupHeight - 8;

          // If too close to top of viewport, flip to render below selection
          if (y < 10) {
            y = rect.bottom + 8;
          }

          // Constrain horizontally within viewport
          x = Math.max(12, Math.min(window.innerWidth - popupWidth - 12, x));

          setPosition({ x, y });
          setSelectedText(text);
          setVisible(true);
        } catch {
          setVisible(false);
        }
      }, 80);
    };

    const handleMouseDown = (e: MouseEvent) => {
      if (popupRef.current && popupRef.current.contains(e.target as Node)) {
        return;
      }
      setVisible(false);
    };

    const handleScroll = () => {
      // Hide on scroll to prevent detached floating tooltips
      if (visible) {
        setVisible(false);
      }
    };

    document.addEventListener('selectionchange', handleSelectionChange);
    document.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('scroll', handleScroll, true);

    return () => {
      clearTimeout(timeoutId);
      document.removeEventListener('selectionchange', handleSelectionChange);
      document.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('scroll', handleScroll, true);
    };
  }, [visible]);

  const handleActionClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (!selectedText) return;

    if (onSendToDecoder) {
      onSendToDecoder(selectedText);
    } else {
      // Fallback: dispatch custom event if no callback passed
      window.dispatchEvent(
        new CustomEvent('fs-send-to-decoder', {
          detail: { text: selectedText }
        })
      );
    }

    // Clear selection
    window.getSelection()?.removeAllRanges();
    setVisible(false);
  };

  if (!visible) return null;

  return (
    <div
      ref={popupRef}
      style={{
        position: 'fixed',
        left: `${position.x}px`,
        top: `${position.y}px`,
        zIndex: 99999
      }}
      className="animate-in fade-in zoom-in-95 duration-150 select-none pointer-events-auto"
    >
      <button
        onClick={handleActionClick}
        className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900/95 hover:bg-slate-950 text-white text-xs font-semibold shadow-xl border border-slate-700/80 backdrop-blur-md cursor-pointer hover:scale-105 active:scale-95 transition-all group ring-2 ring-indigo-500/30"
        title="Send highlighted text to Decoder"
      >
        <span className="p-1 rounded-full bg-indigo-600/80 text-white shrink-0 group-hover:bg-indigo-500 transition-colors">
          <Binary className="w-3 h-3" />
        </span>
        <span className="font-sans font-medium text-slate-100">Send to Decoder</span>
        <ArrowRight className="w-3 h-3 text-slate-400 group-hover:text-white group-hover:translate-x-0.5 transition-transform" />
      </button>
    </div>
  );
};
