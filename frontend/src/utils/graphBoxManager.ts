import { EntityGroupBox } from '../types';

export interface GroupBoxColor {
  id: string;
  name: string;
  borderColor: string;
  bgColor: string;
  headerBg: string;
  textColor: string;
  badgeBg: string;
}

export const GROUP_BOX_PALETTES: Record<string, GroupBoxColor> = {
  indigo: {
    id: 'indigo',
    name: 'Indigo (Primary)',
    borderColor: '#6366f1',
    bgColor: 'rgba(99, 102, 241, 0.09)',
    headerBg: '#4f46e5',
    textColor: '#ffffff',
    badgeBg: 'rgba(255, 255, 255, 0.25)',
  },
  emerald: {
    id: 'emerald',
    name: 'Emerald (Safe/Verified)',
    borderColor: '#10b981',
    bgColor: 'rgba(16, 185, 129, 0.09)',
    headerBg: '#059669',
    textColor: '#ffffff',
    badgeBg: 'rgba(255, 255, 255, 0.25)',
  },
  rose: {
    id: 'rose',
    name: 'Rose (Critical/Threat)',
    borderColor: '#f43f5e',
    bgColor: 'rgba(244, 63, 94, 0.09)',
    headerBg: '#e11d48',
    textColor: '#ffffff',
    badgeBg: 'rgba(255, 255, 255, 0.25)',
  },
  amber: {
    id: 'amber',
    name: 'Amber (Suspicious)',
    borderColor: '#f59e0b',
    bgColor: 'rgba(245, 158, 11, 0.09)',
    headerBg: '#d97706',
    textColor: '#ffffff',
    badgeBg: 'rgba(255, 255, 255, 0.25)',
  },
  purple: {
    id: 'purple',
    name: 'Purple (Actor Cluster)',
    borderColor: '#a855f7',
    bgColor: 'rgba(168, 85, 247, 0.09)',
    headerBg: '#9333ea',
    textColor: '#ffffff',
    badgeBg: 'rgba(255, 255, 255, 0.25)',
  },
  cyan: {
    id: 'cyan',
    name: 'Cyan (Infrastructure)',
    borderColor: '#06b6d4',
    bgColor: 'rgba(6, 182, 212, 0.09)',
    headerBg: '#0891b2',
    textColor: '#ffffff',
    badgeBg: 'rgba(255, 255, 255, 0.25)',
  },
  slate: {
    id: 'slate',
    name: 'Slate (Neutral)',
    borderColor: '#64748b',
    bgColor: 'rgba(100, 116, 139, 0.09)',
    headerBg: '#475569',
    textColor: '#ffffff',
    badgeBg: 'rgba(255, 255, 255, 0.25)',
  },
};

const PALETTE_KEYS = Object.keys(GROUP_BOX_PALETTES);

/**
 * Calculates optimal grid positions for member nodes inside a bounding box
 * dynamically adjusting spacing based on box dimensions.
 */
export function layoutNodesInsideBox(
  box: { x: number; y: number; width: number; height: number; nodeIds: string[] },
  currentPositions: Record<string, { x: number; y: number }>
): Record<string, { x: number; y: number }> {
  const updatedPositions = { ...currentPositions };
  const n = box.nodeIds.length;
  if (n === 0) return updatedPositions;

  const headerH = 46;
  const padX = 40;
  const padY = 32;

  const contentW = Math.max(80, box.width - padX * 2);
  const contentH = Math.max(60, box.height - headerH - padY * 2);

  // Compute number of columns & rows based on aspect ratio
  const ratio = contentW / Math.max(1, contentH);
  let cols = Math.max(1, Math.min(n, Math.round(Math.sqrt(n * ratio))));
  if (cols < 1) cols = 1;
  const rows = Math.ceil(n / cols);

  box.nodeIds.forEach((nodeId, idx) => {
    const r = Math.floor(idx / cols);
    const c = idx % cols;

    // Center items in the last row if sparse
    const itemsInThisRow = r === rows - 1 ? (n % cols || cols) : cols;
    const rowOffset = ((cols - itemsInThisRow) / 2) * (contentW / cols);

    const x = box.x + padX + rowOffset + ((c + 0.5) / cols) * contentW;
    const y = box.y + headerH + padY + ((r + 0.5) / rows) * contentH;

    updatedPositions[nodeId] = {
      x: Math.round(x * 10) / 10,
      y: Math.round(y * 10) / 10,
    };
  });

  return updatedPositions;
}

/**
 * Creates a new interactive grouping enclosure box containing the selected nodes.
 * Stores original node positions for exact restoration upon ungrouping.
 */
export function createEntityGroupBox(
  selectedNodeIds: string[],
  currentPositions: Record<string, { x: number; y: number }>,
  existingBoxesCount: number
): { box: EntityGroupBox; updatedPositions: Record<string, { x: number; y: number }> } {
  const nodeIds = [...selectedNodeIds];

  // Store original positions for ungroup restoration
  const originalPositions: Record<string, { x: number; y: number }> = {};
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;

  nodeIds.forEach((id) => {
    const p = currentPositions[id];
    if (p) {
      originalPositions[id] = { x: p.x, y: p.y };
      if (p.x < minX) minX = p.x;
      if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.y > maxY) maxY = p.y;
    }
  });

  if (minX === Infinity) {
    minX = 200;
    maxX = 500;
    minY = 150;
    maxY = 350;
  }

  const headerH = 46;
  const padX = 46;
  const padY = 40;

  const rawW = maxX - minX + padX * 2;
  const rawH = maxY - minY + headerH + padY * 2;

  const width = Math.max(260, Math.round(rawW));
  const height = Math.max(180, Math.round(rawH));
  const x = Math.round(minX - padX);
  const y = Math.round(minY - headerH - padY);

  const paletteKey = PALETTE_KEYS[existingBoxesCount % PALETTE_KEYS.length];
  const boxId = `box_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const title = `Group ${existingBoxesCount + 1}`;

  const newBox: EntityGroupBox = {
    id: boxId,
    title,
    color: paletteKey,
    x,
    y,
    width,
    height,
    nodeIds,
    originalPositions,
  };

  // Neatly arrange nodes inside the box with uniform spacing
  const updatedPositions = layoutNodesInsideBox(newBox, currentPositions);

  return {
    box: newBox,
    updatedPositions,
  };
}

/**
 * Resizes the box to new dimensions and dynamically recalculates node spacing inside.
 */
export function resizeEntityGroupBox(
  box: EntityGroupBox,
  newWidth: number,
  newHeight: number,
  currentPositions: Record<string, { x: number; y: number }>
): { updatedBox: EntityGroupBox; updatedPositions: Record<string, { x: number; y: number }> } {
  const minW = 200;
  const minH = 140;

  const clampedW = Math.max(minW, Math.round(newWidth));
  const clampedH = Math.max(minH, Math.round(newHeight));

  const updatedBox: EntityGroupBox = {
    ...box,
    width: clampedW,
    height: clampedH,
  };

  const updatedPositions = layoutNodesInsideBox(updatedBox, currentPositions);

  return {
    updatedBox,
    updatedPositions,
  };
}

/**
 * Translates the box and all enclosed nodes simultaneously by delta coordinates.
 */
export function moveEntityGroupBox(
  box: EntityGroupBox,
  deltaX: number,
  deltaY: number,
  currentPositions: Record<string, { x: number; y: number }>
): { updatedBox: EntityGroupBox; updatedPositions: Record<string, { x: number; y: number }> } {
  const updatedBox: EntityGroupBox = {
    ...box,
    x: Math.round((box.x + deltaX) * 10) / 10,
    y: Math.round((box.y + deltaY) * 10) / 10,
  };

  const updatedPositions = { ...currentPositions };
  box.nodeIds.forEach((nid) => {
    const curr = currentPositions[nid];
    if (curr) {
      updatedPositions[nid] = {
        x: Math.round((curr.x + deltaX) * 10) / 10,
        y: Math.round((curr.y + deltaY) * 10) / 10,
      };
    }
  });

  return {
    updatedBox,
    updatedPositions,
  };
}

/**
 * Ungroups the box and restores all contained nodes to their exact previous state before grouping.
 */
export function ungroupEntityGroupBox(
  box: EntityGroupBox,
  currentPositions: Record<string, { x: number; y: number }>
): Record<string, { x: number; y: number }> {
  const restoredPositions = { ...currentPositions };
  box.nodeIds.forEach((nid) => {
    if (box.originalPositions && box.originalPositions[nid]) {
      restoredPositions[nid] = { ...box.originalPositions[nid] };
    }
  });
  return restoredPositions;
}
