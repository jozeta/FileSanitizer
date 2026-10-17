/**
 * entityNormalizer.ts
 *
 * Normalizes, groups similar graph entities, and establishes parent-child
 * hierarchy trees across Entity Graph and Threat Graph.
 *
 * Identifies duplicate or equivalent indicators across network/web (URLs, domains, hostnames),
 * IP addresses, emails, hashes, file paths, and usernames.
 *
 * Automatically constructs semantic parent-child hierarchies:
 * - Domain -> Child Endpoints / URLs (e.g. domain.com -> domain.com/site1, domain.com/site2)
 * - Root Domain -> Subdomains (e.g. domain.com -> api.domain.com, mail.domain.com)
 * - IP -> IP Ports / Service Endpoints (e.g. 192.168.1.1 -> 192.168.1.1:8080)
 * - File -> Embedded / Carved Files (e.g. sample.docx -> embedded.bin)
 * - Process -> Child Processes
 */

export interface GroupableNode {
  id: string;
  label: string;
  full_label?: string;
  type: string;
  risk?: string;
  details?: Record<string, any>;
  groupedCount?: number;
  groupedVariants?: string[];
  groupedNodes?: any[];
  // Hierarchy & Parent-Child Tree Fields
  parentId?: string | null;
  parentLabel?: string | null;
  parentType?: string | null;
  isChild?: boolean;
  childIds?: string[];
  childrenCount?: number;
  childNodes?: any[];
  treeLevel?: number;
  hierarchyRelation?: 'child_endpoint' | 'subdomain' | 'service_port' | 'child_process' | 'embedded_content' | string;
  is_shared?: boolean;
  [key: string]: any;
}

export interface GroupableEdge {
  source: string;
  target: string;
  label?: string;
  type?: string;
  is_hierarchy?: boolean;
  is_shared?: boolean;
  [key: string]: any;
}

/**
 * Extracts a normalized domain or host from a URL or raw text string.
 */
export function extractDomainFromUrlOrText(raw: string): string | null {
  if (!raw) return null;
  let text = String(raw).trim();
  // Strip protocol
  text = text.replace(/^(https?|ftp|sftp|ws|wss):\/\//i, '');
  // Take authority part before slash, query, or hash
  const slashIdx = text.indexOf('/');
  const qIdx = text.indexOf('?');
  const hIdx = text.indexOf('#');
  let endIdx = text.length;
  if (slashIdx !== -1 && slashIdx < endIdx) endIdx = slashIdx;
  if (qIdx !== -1 && qIdx < endIdx) endIdx = qIdx;
  if (hIdx !== -1 && hIdx < endIdx) endIdx = hIdx;
  const authority = text.substring(0, endIdx);
  // Strip port
  const host = authority.split(':')[0].trim().toLowerCase();
  return host || null;
}

/**
 * Returns the normalized comparison key and semantic family for an entity node.
 */
export function getNormalizedEntityKey(node: GroupableNode): { family: string; key: string } | null {
  const type = (node.type || '').toLowerCase();
  const rawText = (node.full_label || node.label || node.id || '').trim();

  if (!rawText) return null;

  // Never merge root/file anchors
  if (type === 'file' || node.id === 'root' || type === 'root') {
    return null;
  }

  // 1. Web & Network Family (URL, Domain, Hostname)
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

    return {
      family: 'web_network',
      key: cleaned
    };
  }

  // 2. IP Addresses Family
  if (type === 'ip') {
    let cleaned = rawText.toLowerCase();
    cleaned = cleaned.replace(/^::ffff:/i, '');
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
    cleaned = cleaned.replace(/^.*[\\/]/, '');
    return {
      family: 'user',
      key: cleaned
    };
  }

  // 7. ATT&CK Techniques / TTPs
  if (type === 'technique') {
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

export function parseIpv4ToNumber(ip: string): number | null {
  if (!ip) return null;
  const clean = ip.trim().replace(/^::ffff:/i, '').split(':')[0].trim();
  const parts = clean.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) | octet;
  }
  return num >>> 0;
}

export function parseSubnetBlock(str: string): { netNum: number; mask: number; prefixLen: number; label: string } | null {
  if (!str) return null;
  const clean = str.trim();

  // Match e.g. "10.10.10.0/24" or "10.10.10.0" or "Network 10.10.10.0/24"
  const cidrMatch = clean.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2}))?/);
  if (!cidrMatch) return null;

  const ipStr = cidrMatch[1];
  let prefix = cidrMatch[2] ? parseInt(cidrMatch[2], 10) : null;

  if (prefix === null) {
    if (ipStr.endsWith('.0')) {
      const parts = ipStr.split('.');
      if (parts[1] === '0' && parts[2] === '0' && parts[3] === '0') prefix = 8;
      else if (parts[2] === '0' && parts[3] === '0') prefix = 16;
      else prefix = 24;
    } else {
      return null;
    }
  }

  if (prefix < 0 || prefix > 32) return null;

  const baseNum = parseIpv4ToNumber(ipStr);
  if (baseNum === null) return null;

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const netNum = (baseNum & mask) >>> 0;

  return { netNum, mask, prefixLen: prefix, label: `${ipStr}/${prefix}` };
}

export function isIpInSubnet(ipStr: string, subnetStr: string): boolean {
  const ipNum = parseIpv4ToNumber(ipStr);
  if (ipNum === null) return false;
  const subnet = parseSubnetBlock(subnetStr);
  if (!subnet) return false;
  return ((ipNum & subnet.mask) >>> 0) === subnet.netNum;
}

/**
 * Builds and enriches parent-child hierarchies across graph nodes and edges.
 *
 * Automatically infers:
 * - Subnet -> Host IPs (10.10.10.0/24 -> 10.10.10.34, but not 10.10.20.12)
 * - Domain -> Child Endpoints (domain.com -> domain.com/site1, domain.com/site2)
 * - Domain -> Subdomains (domain.com -> api.domain.com)
 * - IP -> IP Ports (1.2.3.4 -> 1.2.3.4:8080)
 * - File -> Embedded / Carved Files
 * - Process -> Child Processes
 */
export function buildEntityHierarchy<TNode extends GroupableNode, TEdge extends GroupableEdge>(
  nodes: TNode[],
  edges: TEdge[]
): { nodes: TNode[]; edges: TEdge[] } {
  if (!nodes || nodes.length === 0) {
    return { nodes, edges };
  }

  // Clone nodes to allow safe mutation of hierarchy metadata
  const clonedNodes: TNode[] = nodes.map(n => ({
    ...n,
    childIds: Array.isArray(n.childIds) ? [...n.childIds] : [],
    childrenCount: n.childrenCount ?? (Array.isArray(n.childIds) ? n.childIds.length : 0),
    childNodes: [],
    treeLevel: n.treeLevel ?? (n.id === 'root' || n.type === 'file' ? 0 : (n.isChild ? 2 : 1)),
  }));

  const nodeMap = new Map<string, TNode>(clonedNodes.map(n => [n.id, n]));
  const edgeKeySet = new Set<string>();
  const clonedEdges: TEdge[] = edges.map(e => {
    edgeKeySet.add(`${e.source}->${e.target}`);
    return { ...e };
  });

  // 1. Identify Domain Nodes & Map by canonical host
  const domainNodes: TNode[] = clonedNodes.filter(n => n.type === 'domain' || Boolean(n.details?.domain));
  const domainLookup = new Map<string, TNode>();

  domainNodes.forEach(dn => {
    const rawDom = dn.details?.domain || dn.full_label || dn.label || '';
    const cleanDom = extractDomainFromUrlOrText(rawDom);
    if (cleanDom) {
      domainLookup.set(cleanDom, dn);
    }
  });

  // 2. Identify IP Nodes
  const ipNodes: TNode[] = clonedNodes.filter(n => n.type === 'ip' || Boolean(n.details?.ip));
  const ipLookup = new Map<string, TNode>();
  ipNodes.forEach(ipn => {
    const rawIp = (ipn.details?.ip || ipn.full_label || ipn.label || '').trim().toLowerCase();
    const cleanIp = rawIp.replace(/^::ffff:/i, '').split(':')[0].trim();
    if (cleanIp) {
      ipLookup.set(cleanIp, ipn);
    }
  });

  // Helper to establish parent -> child relationship
  const linkParentChild = (
    parentNode: TNode,
    childNode: TNode,
    relation: 'child_endpoint' | 'subdomain' | 'service_port' | 'child_process' | 'embedded_content' | string,
    edgeLabel: string
  ) => {
    if (parentNode.id === childNode.id) return;

    // Set child fields
    childNode.parentId = parentNode.id;
    childNode.parentLabel = parentNode.full_label || parentNode.label;
    childNode.parentType = parentNode.type;
    childNode.isChild = true;
    childNode.hierarchyRelation = relation;
    childNode.treeLevel = (parentNode.treeLevel ?? 1) + 1;

    // Register on parent
    if (!parentNode.childIds) parentNode.childIds = [];
    if (!parentNode.childIds.includes(childNode.id)) {
      parentNode.childIds.push(childNode.id);
    }
    parentNode.childrenCount = parentNode.childIds.length;

    // Ensure edge exists in graph
    const edgeKey = `${parentNode.id}->${childNode.id}`;
    if (!edgeKeySet.has(edgeKey)) {
      edgeKeySet.add(edgeKey);
      clonedEdges.push({
        source: parentNode.id,
        target: childNode.id,
        label: edgeLabel,
        type: 'parent_child',
        is_hierarchy: true,
      } as TEdge);
    } else {
      // Mark existing edge as hierarchy
      const existingEdge = clonedEdges.find(e => e.source === parentNode.id && e.target === childNode.id);
      if (existingEdge) {
        existingEdge.is_hierarchy = true;
        if (!existingEdge.type || existingEdge.type === 'references' || existingEdge.type === 'connects') {
          existingEdge.type = 'parent_child';
        }
      }
    }
  };

  // 3. Process URL Nodes -> Link under matching Domain
  clonedNodes.forEach(node => {
    if (node.type === 'url' || (!node.parentId && (node.full_label || node.label || '').includes('/'))) {
      const urlText = node.details?.url || node.full_label || node.label || '';
      const host = extractDomainFromUrlOrText(urlText);
      if (host && domainLookup.has(host)) {
        const parentDom = domainLookup.get(host)!;
        if (parentDom.id !== node.id) {
          linkParentChild(parentDom, node, 'child_endpoint', 'child endpoint');
        }
      }
    }
  });

  // 4. Process IP Subnet Hierarchy
  // Collect all subnet/network nodes in the graph
  const subnetNodes: { node: TNode; subnet: ReturnType<typeof parseSubnetBlock> }[] = [];
  clonedNodes.forEach(node => {
    const rawCidr = node.details?.cidr || (Array.isArray(node.details?.cidrs) ? node.details.cidrs[0] : null);
    const rawVal = rawCidr || node.full_label || node.label || '';
    const isNetType = node.type === 'network' || node.type === 'subnet';
    const parsed = parseSubnetBlock(rawVal) || (isNetType ? parseSubnetBlock(node.details?.ip || '') : null);
    if (parsed) {
      subnetNodes.push({ node, subnet: parsed });
    }
  });

  // Link host IP nodes to the most specific matching subnet
  clonedNodes.forEach(node => {
    if (node.parentId) return;
    const rawIp = (node.details?.ip || node.details?.ip_address || node.full_label || node.label || '').trim();
    const cleanIp = rawIp.replace(/^::ffff:/i, '').split(':')[0].trim();
    const ipNum = parseIpv4ToNumber(cleanIp);
    if (ipNum === null) return;

    // Find all candidate subnets that contain this IP and IP is not the subnet itself
    const candidateSubnets = subnetNodes.filter(s => {
      if (s.node.id === node.id || !s.subnet) return false;
      return ((ipNum & s.subnet.mask) >>> 0) === s.subnet.netNum && ipNum !== s.subnet.netNum;
    });

    if (candidateSubnets.length > 0) {
      // Pick most specific subnet (highest prefixLen)
      candidateSubnets.sort((a, b) => (b.subnet?.prefixLen ?? 0) - (a.subnet?.prefixLen ?? 0));
      const bestSubnet = candidateSubnets[0].node;
      linkParentChild(bestSubnet, node, 'subnet_member', 'subnet member');
    }
  });

  // 4. Process URL Nodes -> Link under matching Domain
  clonedNodes.forEach(node => {
    if (node.type === 'url' || (!node.parentId && (node.full_label || node.label || '').includes('/'))) {
      const urlText = node.details?.url || node.full_label || node.label || '';
      const host = extractDomainFromUrlOrText(urlText);
      if (host && domainLookup.has(host)) {
        const parentDom = domainLookup.get(host)!;
        if (parentDom.id !== node.id) {
          linkParentChild(parentDom, node, 'child_endpoint', 'child endpoint');
        }
      }
    }
  });

  // 5. Process Subdomains -> Link under closest Parent Domain
  // Sort candidate parent domains by length descending so the most specific immediate parent domain is matched first
  const sortedDomainHosts = Array.from(domainLookup.keys()).sort((a, b) => b.length - a.length);
  domainNodes.forEach(subNode => {
    const rawSub = subNode.details?.domain || subNode.full_label || subNode.label || '';
    const cleanSub = extractDomainFromUrlOrText(rawSub);
    if (!cleanSub || subNode.parentId) return;

    // Look for immediate closest parent domain where cleanSub.endsWith('.' + parentHost)
    for (const parentHost of sortedDomainHosts) {
      if (cleanSub !== parentHost && cleanSub.endsWith('.' + parentHost)) {
        const rootNode = domainLookup.get(parentHost);
        if (rootNode && rootNode.id !== subNode.id) {
          linkParentChild(rootNode, subNode, 'subdomain', 'subdomain of');
          break;
        }
      }
    }
  });

  // 6. Process IP Ports / Endpoints -> Link under parent IP
  clonedNodes.forEach(node => {
    if (node.parentId) return;
    const raw = (node.full_label || node.label || '').trim();
    if (raw.includes(':') && /\d+$/.test(raw)) {
      const ipPart = raw.split(':')[0].trim().toLowerCase();
      if (ipLookup.has(ipPart)) {
        const parentIp = ipLookup.get(ipPart)!;
        if (parentIp.id !== node.id) {
          linkParentChild(parentIp, node, 'service_port', 'service port');
        }
      }
    }
  });

  // 7. Process Embedded / Carved Files -> Link under root/file node
  const rootNode = clonedNodes.find(n => n.id === 'root' || n.type === 'file');
  if (rootNode) {
    clonedNodes.forEach(node => {
      if (node.type === 'embedded_file' && !node.parentId) {
        linkParentChild(rootNode, node, 'embedded_content', 'carved payload');
      }
    });
  }

  // 8. Re-hydrate childNodes array on parent nodes with full child node objects
  clonedNodes.forEach(node => {
    if (node.childIds && node.childIds.length > 0) {
      node.childNodes = node.childIds
        .map(cid => nodeMap.get(cid))
        .filter((c): c is TNode => Boolean(c));
      node.childrenCount = node.childNodes.length;
    }
  });

  return {
    nodes: clonedNodes,
    edges: clonedEdges,
  };
}

/**
 * Groups and merges similar nodes in a graph, preserving all data for individual member nodes
 * and maintaining parent-child hierarchy across consolidated entities.
 *
 * @param nodes List of graph nodes
 * @param edges List of graph edges
 * @param enabled When false, returns nodes and edges with hierarchy enriched but unmerged
 * @returns Consolidated nodes and re-pointed deduplicated edges
 */
export function groupSimilarNodesInGraph<TNode extends GroupableNode, TEdge extends GroupableEdge>(
  nodes: TNode[],
  edges: TEdge[],
  enabled: boolean = true
): { nodes: TNode[]; edges: TEdge[]; mergedCount: number } {
  if (!nodes || nodes.length === 0) {
    return { nodes: [], edges: [], mergedCount: 0 };
  }

  // If grouping is disabled, still establish parent-child hierarchy!
  if (!enabled || nodes.length <= 1) {
    const hierarchized = buildEntityHierarchy(nodes, edges);
    return {
      nodes: hierarchized.nodes,
      edges: hierarchized.edges,
      mergedCount: 0,
    };
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

  groups.forEach((groupNodes) => {
    if (groupNodes.length === 1) {
      finalNodes.push(groupNodes[0]);
      return;
    }

    // Merge multiple similar nodes!
    mergedGroupCount += (groupNodes.length - 1);

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
      return (a.label || a.id).length - (b.label || b.id).length;
    });

    const primaryNode = sortedByPriority[0];
    const compositeId = primaryNode.id;

    // Collect all variants
    const allVariants = Array.from(
      new Set(groupNodes.map(n => n.full_label || n.label || n.id).filter(Boolean))
    );

    // Map all old IDs in this group to the compositeId
    groupNodes.forEach(n => {
      oldIdToNewId.set(n.id, compositeId);
    });

    // Merge childIds across all group members
    const mergedChildIds = Array.from(
      new Set(groupNodes.flatMap(n => n.childIds || []))
    ).filter(cid => !groupNodes.some(gn => gn.id === cid));

    // Inherit parent info if present on any member
    const parentNodeInfo = groupNodes.find(n => n.parentId && !groupNodes.some(gn => gn.id === n.parentId));

    // Create composite node with all original member nodes preserved in groupedNodes
    const compositeNode = {
      ...primaryNode,
      id: compositeId,
      groupedCount: groupNodes.length,
      groupedVariants: allVariants,
      groupedNodes: groupNodes, // Full objects with complete metadata/details preserved
      childIds: mergedChildIds,
      childrenCount: mergedChildIds.length,
      parentId: parentNodeInfo?.parentId || primaryNode.parentId || null,
      parentLabel: parentNodeInfo?.parentLabel || primaryNode.parentLabel || null,
      parentType: parentNodeInfo?.parentType || primaryNode.parentType || null,
      isChild: Boolean(parentNodeInfo?.parentId || primaryNode.parentId),
      hierarchyRelation: parentNodeInfo?.hierarchyRelation || primaryNode.hierarchyRelation,
      is_shared: groupNodes.some(n => n.is_shared),
    } as TNode;

    finalNodes.push(compositeNode);
  });

  // Re-wire and deduplicate edges
  const edgeKeySet = new Set<string>();
  const finalEdges: TEdge[] = [];

  edges.forEach(edge => {
    const newSource = oldIdToNewId.get(edge.source) || edge.source;
    const newTarget = oldIdToNewId.get(edge.target) || edge.target;

    if (newSource === newTarget) {
      return;
    }

    const edgeDedupeKey = `${newSource}-->${newTarget}:::${edge.type || edge.label || ''}`;
    if (!edgeKeySet.has(edgeDedupeKey)) {
      edgeKeySet.add(edgeDedupeKey);
      finalEdges.push({
        ...edge,
        source: newSource,
        target: newTarget,
      });
    }
  });

  // Run hierarchy enrichment on the consolidated graph
  const hierarchized = buildEntityHierarchy(finalNodes, finalEdges);

  return {
    nodes: hierarchized.nodes,
    edges: hierarchized.edges,
    mergedCount: mergedGroupCount,
  };
}
