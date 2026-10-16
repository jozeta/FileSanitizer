/**
 * entityNormalizer.ts
 *
 * Normalizes and groups similar graph entities across Entity Graph and Threat Graph.
 * Identifies duplicate or equivalent indicators across network/web (URLs, domains, hostnames),
 * IP addresses, emails, hashes, file paths, and usernames.
 */

export interface GroupableNode {
  id: string;
  label: string;
  full_label?: string;
  type: string;
  risk?: string;
  groupedCount?: number;
  groupedVariants?: string[];
  groupedNodes?: any[];
  [key: string]: any;
}

export interface GroupableEdge {
  source: string;
  target: string;
  label?: string;
  type?: string;
  is_shared?: boolean;
  [key: string]: any;
}

/**
 * Returns the normalized comparison key and semantic family for an entity node.
 */
export function getNormalizedEntityKey(node: GroupableNode): { family: string; key: string } | null {
  const type = (node.type || '').toLowerCase();
  const rawText = (node.label || node.full_label || node.id || '').trim();

  if (!rawText) return null;

  // Never merge root/file anchors
  if (type === 'file' || node.id === 'root' || type === 'root') {
    return null;
  }

  // 1. Web & Network Family (URL, Domain, Hostname)
  // Normalizes http://www.google.com, https://www.google.com/, www.google.com, and google.com to google.com
  if (['url', 'domain', 'hostname'].includes(type)) {
    let cleaned = rawText.toLowerCase();

    // Strip scheme
    cleaned = cleaned.replace(/^(https?|ftp|sftp|ws|wss):\/\//i, '');

    // Strip leading www.
    cleaned = cleaned.replace(/^www\./i, '');

    // Strip standard port
    cleaned = cleaned.replace(/:(80|443|8080|8443)$/, '');

    // Strip trailing slashes
    cleaned = cleaned.replace(/\/+$/, '');

    // If string still has query or fragment, strip them if matching root
    // For pure hostname/domain equivalence:
    if (cleaned.endsWith('/')) {
      cleaned = cleaned.slice(0, -1);
    }

    return {
      family: 'web_network',
      key: cleaned
    };
  }

  // 2. IP Addresses Family
  if (type === 'ip') {
    let cleaned = rawText.toLowerCase();
    // Strip IPv4-mapped IPv6 prefix
    cleaned = cleaned.replace(/^::ffff:/i, '');
    // Strip port suffix (e.g. 192.168.1.1:8080)
    cleaned = cleaned.replace(/:\d+$/, '');
    return {
      family: 'ip_address',
      key: cleaned
    };
  }

  // 3. Email Addresses Family
  if (type === 'email') {
    let cleaned = rawText.toLowerCase().replace(/^mailto:/i, '');
    return {
      family: 'email',
      key: cleaned
    };
  }

  // 4. Hashes Family (MD5, SHA1, SHA256)
  if (type === 'hash') {
    return {
      family: 'hash',
      key: rawText.toLowerCase()
    };
  }

  // 5. File Paths / Embedded Files
  if (['embedded_file', 'artifact', 'share'].includes(type)) {
    let cleaned = rawText.toLowerCase().replace(/\\/g, '/');
    cleaned = cleaned.replace(/\/+/g, '/');
    return {
      family: 'filepath',
      key: cleaned
    };
  }

  // 6. Usernames / Identity
  if (['user', 'username', 'person'].includes(type)) {
    let cleaned = rawText.toLowerCase();
    // Strip domain prefix e.g. CONTOSO\JohnDoe -> johndoe
    cleaned = cleaned.replace(/^.*[\\/]/, '');
    return {
      family: 'user',
      key: cleaned
    };
  }

  // 7. ATT&CK Techniques / TTPs
  if (type === 'technique') {
    // Extract technique ID e.g. T1059.001
    const match = rawText.match(/T\d{4}(?:\.\d{3})?/i);
    if (match) {
      return {
        family: 'technique',
        key: match[0].toUpperCase()
      };
    }
  }

  // 8. Signatures & Keywords
  if (['threat_intel', 'threat_signature', 'keyword', 'watchlist_keyword'].includes(type)) {
    return {
      family: 'threat_keyword',
      key: rawText.toLowerCase().replace(/\s+/g, ' ')
    };
  }

  return null;
}

/**
 * Groups and merges similar nodes in a graph.
 *
 * @param nodes List of graph nodes
 * @param edges List of graph edges
 * @param enabled When false, returns nodes and edges unmodified
 * @returns Consolidated nodes and re-pointed deduplicated edges
 */
export function groupSimilarNodesInGraph<TNode extends GroupableNode, TEdge extends GroupableEdge>(
  nodes: TNode[],
  edges: TEdge[],
  enabled: boolean = true
): { nodes: TNode[]; edges: TEdge[]; mergedCount: number } {
  if (!enabled || nodes.length <= 1) {
    return { nodes, edges, mergedCount: 0 };
  }

  // Group nodes by family and normalized key
  const groups = new Map<string, TNode[]>();
  const unmergedNodes: TNode[] = [];

  nodes.forEach(node => {
    const norm = getNormalizedEntityKey(node);
    if (!norm || !norm.key) {
      unmergedNodes.push(node);
      return;
    }

    const groupKey = `${norm.family}:::${norm.key}`;
    const existing = groups.get(groupKey);
    if (existing) {
      existing.push(node);
    } else {
      groups.set(groupKey, [node]);
    }
  });

  const finalNodes: TNode[] = [...unmergedNodes];
  const oldIdToNewId = new Map<string, string>();
  let mergedGroupCount = 0;

  groups.forEach((groupNodes, _groupKey) => {
    if (groupNodes.length === 1) {
      // Only 1 node in this group, no merging needed
      finalNodes.push(groupNodes[0]);
      return;
    }

    // Merge multiple similar nodes!
    mergedGroupCount += (groupNodes.length - 1);

    // Pick primary representative: prefer shortest canonical label (e.g. google.com over http://www.google.com:80)
    // or highest risk severity
    const riskWeight = (r?: string) => {
      switch ((r || '').toLowerCase()) {
        case 'critical': return 5;
        case 'high': return 4;
        case 'warning':
        case 'medium': return 3;
        case 'low': return 2;
        default: return 1;
      }
    };

    const sortedByPriority = [...groupNodes].sort((a, b) => {
      const rwDiff = riskWeight(b.risk) - riskWeight(a.risk);
      if (rwDiff !== 0) return rwDiff;
      // Prefer shortest clean label
      return (a.label || a.id).length - (b.label || b.id).length;
    });

    const primaryNode = sortedByPriority[0];
    const compositeId = primaryNode.id;

    // Collect all variants
    const allVariants = Array.from(
      new Set(groupNodes.map(n => n.label || n.full_label || n.id).filter(Boolean))
    );

    // Map all old IDs in this group to the compositeId
    groupNodes.forEach(n => {
      oldIdToNewId.set(n.id, compositeId);
    });

    // Create composite node with grouped indicators
    const compositeNode = {
      ...primaryNode,
      id: compositeId,
      groupedCount: groupNodes.length,
      groupedVariants: allVariants,
      groupedNodes: groupNodes,
      // If any node in group was marked shared, whole group is shared
      is_shared: groupNodes.some(n => n.is_shared)
    } as TNode;

    finalNodes.push(compositeNode);
  });

  // Re-wire and deduplicate edges
  const edgeKeySet = new Set<string>();
  const finalEdges: TEdge[] = [];

  edges.forEach(edge => {
    const newSource = oldIdToNewId.get(edge.source) || edge.source;
    const newTarget = oldIdToNewId.get(edge.target) || edge.target;

    // Avoid self-loops created by merging connected nodes in the same group
    if (newSource === newTarget) {
      return;
    }

    const edgeDedupeKey = `${newSource}-->${newTarget}:::${edge.type || edge.label || ''}`;
    if (!edgeKeySet.has(edgeDedupeKey)) {
      edgeKeySet.add(edgeDedupeKey);
      finalEdges.push({
        ...edge,
        source: newSource,
        target: newTarget
      });
    }
  });

  return {
    nodes: finalNodes,
    edges: finalEdges,
    mergedCount: mergedGroupCount
  };
}
