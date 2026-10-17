import React, { useState } from 'react';
import { EntityGroupBox } from '../types';
import { GROUP_BOX_PALETTES } from '../utils/graphBoxManager';
import { Move, Edit2, Check, X, Palette, Unlink } from 'lucide-react';

interface EntityGroupBoxOverlayProps {
  boxes: EntityGroupBox[];
  onStartMoveBox: (e: React.MouseEvent, boxId: string) => void;
  onStartResizeBox: (e: React.MouseEvent, boxId: string) => void;
  onRenameBox: (boxId: string, newTitle: string) => void;
  onChangeColorBox: (boxId: string, newColorKey: string) => void;
  onUngroupBox: (boxId: string) => void;
  selectedBoxId?: string | null;
  onSelectBox?: (boxId: string) => void;
}

export const EntityGroupBoxOverlay: React.FC<EntityGroupBoxOverlayProps> = ({
  boxes,
  onStartMoveBox,
  onStartResizeBox,
  onRenameBox,
  onChangeColorBox,
  onUngroupBox,
  selectedBoxId,
  onSelectBox,
}) => {
  const [editingBoxId, setEditingBoxId] = useState<string | null>(null);
  const [editTitle, setEditTitle] = useState<string>('');
  const [colorPickerBoxId, setColorPickerBoxId] = useState<string | null>(null);

  const handleStartRename = (box: EntityGroupBox, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingBoxId(box.id);
    setEditTitle(box.title);
    setColorPickerBoxId(null);
  };

  const handleSaveRename = (boxId: string, e?: React.MouseEvent | React.FormEvent) => {
    if (e) e.stopPropagation();
    if (editTitle.trim()) {
      onRenameBox(boxId, editTitle.trim());
    }
    setEditingBoxId(null);
  };

  const handleCancelRename = (e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingBoxId(null);
  };

  const handleToggleColorPicker = (boxId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setColorPickerBoxId((prev) => (prev === boxId ? null : boxId));
    setEditingBoxId(null);
  };

  const handlePickColor = (boxId: string, colorKey: string, e: React.MouseEvent) => {
    e.stopPropagation();
    onChangeColorBox(boxId, colorKey);
    setColorPickerBoxId(null);
  };

  const handleUngroup = (boxId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    onUngroupBox(boxId);
  };

  if (!boxes || boxes.length === 0) return null;

  return (
    <g className="entity-group-boxes-layer select-none">
      {boxes.map((box) => {
        const palette = GROUP_BOX_PALETTES[box.color] || GROUP_BOX_PALETTES.indigo;
        const isEditing = editingBoxId === box.id;
        const isColorPickerOpen = colorPickerBoxId === box.id;
        const isSelected = selectedBoxId === box.id;

        return (
          <g
            key={box.id}
            className="group-box-container"
            onClick={(e) => {
              e.stopPropagation();
              onSelectBox?.(box.id);
            }}
          >
            {/* Box Background Enclosure */}
            <rect
              x={box.x}
              y={box.y}
              width={box.width}
              height={box.height}
              rx={16}
              ry={16}
              fill={palette.bgColor}
              stroke={palette.borderColor}
              strokeWidth={isSelected ? 2.5 : 2}
              strokeDasharray="6 3"
              className="transition-colors cursor-move"
              onMouseDown={(e) => onStartMoveBox(e, box.id)}
            />

            {/* Interactive Header Bar embedded via foreignObject */}
            <foreignObject
              x={box.x + 6}
              y={box.y + 6}
              width={Math.max(120, box.width - 12)}
              height={40}
              className="overflow-visible"
            >
              <div
                style={{ backgroundColor: palette.headerBg }}
                className="w-full h-9 rounded-xl text-white px-3 flex items-center justify-between shadow-sm cursor-move gap-2"
                onMouseDown={(e) => onStartMoveBox(e, box.id)}
              >
                {/* Left: Drag grip & Title */}
                <div className="flex items-center gap-1.5 min-w-0 flex-1">
                  <Move className="w-3.5 h-3.5 opacity-80 shrink-0" />
                  {isEditing ? (
                    <div
                      className="flex items-center gap-1 flex-1 min-w-0"
                      onClick={(e) => e.stopPropagation()}
                      onMouseDown={(e) => e.stopPropagation()}
                    >
                      <input
                        type="text"
                        value={editTitle}
                        onChange={(e) => setEditTitle(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleSaveRename(box.id);
                          if (e.key === 'Escape') setEditingBoxId(null);
                        }}
                        autoFocus
                        className="bg-white/20 text-white placeholder-white/60 text-xs px-1.5 py-0.5 rounded outline-none border border-white/40 w-full min-w-[70px] max-w-[130px] font-semibold"
                      />
                      <button
                        type="button"
                        onClick={(e) => handleSaveRename(box.id, e)}
                        className="p-1 hover:bg-white/20 rounded cursor-pointer"
                        title="Save name"
                      >
                        <Check className="w-3 h-3 text-white" />
                      </button>
                      <button
                        type="button"
                        onClick={handleCancelRename}
                        className="p-1 hover:bg-white/20 rounded cursor-pointer"
                        title="Cancel"
                      >
                        <X className="w-3 h-3 text-white/80" />
                      </button>
                    </div>
                  ) : (
                    <div
                      className="flex items-center gap-1.5 min-w-0 group/title cursor-pointer"
                      onClick={(e) => handleStartRename(box, e)}
                      title="Double click or click to rename"
                    >
                      <span className="font-semibold text-xs tracking-tight truncate max-w-[140px]">
                        {box.title}
                      </span>
                      <Edit2 className="w-2.5 h-2.5 opacity-60 group-hover/title:opacity-100 shrink-0 transition-opacity" />
                    </div>
                  )}
                </div>

                {/* Right: Badge, Color, Ungroup Actions */}
                <div
                  className="flex items-center gap-1 shrink-0"
                  onClick={(e) => e.stopPropagation()}
                  onMouseDown={(e) => e.stopPropagation()}
                >
                  {/* Node count pill */}
                  <span
                    style={{ backgroundColor: palette.badgeBg }}
                    className="text-[10px] font-bold px-1.5 py-0.5 rounded-md text-white/95 shrink-0"
                  >
                    {box.nodeIds.length}
                  </span>

                  {/* Color Palette Picker Button */}
                  <div className="relative">
                    <button
                      type="button"
                      onClick={(e) => handleToggleColorPicker(box.id, e)}
                      className="p-1 rounded-md hover:bg-white/20 transition-colors cursor-pointer text-white/90 hover:text-white"
                      title="Change box color"
                    >
                      <Palette className="w-3.5 h-3.5" />
                    </button>

                    {/* Color Swatch Dropdown Popover */}
                    {isColorPickerOpen && (
                      <div className="absolute right-0 top-full mt-1.5 z-50 bg-white rounded-xl shadow-xl border border-slate-200 p-2 flex items-center gap-1.5 min-w-[170px]">
                        {Object.entries(GROUP_BOX_PALETTES).map(([key, pal]) => (
                          <button
                            key={key}
                            type="button"
                            onClick={(e) => handlePickColor(box.id, key, e)}
                            title={pal.name}
                            style={{ backgroundColor: pal.headerBg }}
                            className={`w-5 h-5 rounded-full border-2 transition-transform cursor-pointer hover:scale-110 ${
                              box.color === key ? 'border-slate-800 ring-2 ring-indigo-400' : 'border-white'
                            }`}
                          />
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Ungroup Button */}
                  <button
                    type="button"
                    onClick={(e) => handleUngroup(box.id, e)}
                    className="p-1 rounded-md hover:bg-rose-500/80 transition-colors cursor-pointer text-white/90 hover:text-white flex items-center gap-0.5"
                    title="Ungroup box (restores nodes to previous positions)"
                  >
                    <Unlink className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </foreignObject>

            {/* Bottom-Right Corner Resize Grip Handle */}
            <g
              transform={`translate(${box.x + box.width - 24}, ${box.y + box.height - 24})`}
              className="cursor-nwse-resize select-none"
              onMouseDown={(e) => onStartResizeBox(e, box.id)}
            >
              <rect
                x="0"
                y="0"
                width="20"
                height="20"
                rx="5"
                fill={palette.headerBg}
                fillOpacity="0.88"
                stroke="#ffffff"
                strokeWidth="1.5"
                className="hover:fill-opacity-100 transition-all drop-shadow-2xs"
              />
              <path
                d="M 6 14 L 14 6 M 10 14 L 14 10"
                stroke="#ffffff"
                strokeWidth="1.7"
                strokeLinecap="round"
              />
            </g>
          </g>
        );
      })}
    </g>
  );
};
