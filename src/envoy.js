'use strict';
// Offline Envoy YAML config parser, listener/route/cluster analyzer, static security auditor and Pro report builders.
// Zero Envoy daemon, shell, network or cloud calls.

function stripComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble) return line.slice(0, i);
  }
  return line;
}

function unquote(val) {
  const s = String(val == null ? '' : val).trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function parseScalar(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return '';
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~') return null;
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(',').map((p) => unquote(p)).filter(Boolean);
  }
  return unquote(s);
}

function maskSecrets(str) {
  let out = String(str || '');
  out = out.replace(/(\bBearer\s+)([A-Za-z0-9._~+/=-]{6,})/gi, '$1***');
  out = out.replace(/(\bBasic\s+)([A-Za-z0-9+/=]{6,})/gi, '$1***');
  out = out.replace(/(\b(?:authorization|api_key|apikey|token|password|secret|inline_string)\s*:\s*["']?)([^"'\n]+)/gi, (m, pfx, val) => {
    const v = val.trim();
    if (!v || v === '***' || /^\$\{/.test(v)) return m;
    return `${pfx}***`;
  });
  return out;
}

function parseEnvoy(input, fileName = 'envoy.yaml') {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  const lines = text.split(/\r?\n/);

  const admin = { present: false, address: '', port: '', accessLogPath: '', line: 0, index: 0 };
  const listeners = [];
  const routes = [];
  const clusters = [];
  const rows = [];
  const findings = [];

  let rowIndex = 0;
  let curTop = '';
  let curSection = ''; // 'listeners' | 'clusters' | ''
  let curListener = null;
  let curVhost = null;
  let curRoute = null;
  let curCluster = null;
  let pendingHeaderKey = '';
  let pendingHeaderLine = 0;
  let inEndpoints = false;
  let pendingAddr = '';

  // Indentation stack for path tracking
  const stack = []; // { indent, key }

  const addFinding = (severity, category, rule, line, section, message, rowRef = null) => {
    const f = { severity, category, rule, line, section, message };
    findings.push(f);
    if (rowRef) {
      rowRef.findings.push(f);
      if (severity === 'error') rowRef.errorCount += 1;
      else rowRef.warningCount += 1;
    }
  };

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const rawLine = lines[i];
    const clean = stripComment(rawLine);
    const trimmed = clean.trim();
    if (!trimmed || trimmed === '---' || trimmed === '...') continue;

    const indent = rawLine.search(/\S/);
    while (stack.length && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const isList = trimmed.startsWith('- ');
    const body = isList ? trimmed.slice(2).trim() : trimmed;
    const kv = body.match(/^(['"]?[^:'"]+['"]?)\s*:\s*(.*)$/);
    const key = kv ? unquote(kv[1]) : (stack.length ? stack[stack.length - 1].key : '');
    const rawVal = kv ? kv[2].trim() : body;
    const val = kv ? parseScalar(rawVal) : parseScalar(body);
    const valStr = Array.isArray(val) ? val.join(', ') : String(val == null ? '' : val);

    if (indent === 0 && kv) {
      curTop = key;
      curSection = '';
      curListener = null;
      curVhost = null;
      curRoute = null;
      curCluster = null;
      inEndpoints = false;
      if (key === 'admin') {
        admin.present = true;
        admin.line = lineNo;
      }
    }

    const parentKeys = stack.map((s) => s.key);
    const fullPath = kv ? parentKeys.concat(key) : parentKeys.slice();
    const pathStr = fullPath.join('.');

    if (kv && (!rawVal || rawVal === '{}' || rawVal === '[]')) {
      stack.push({ indent: isList ? indent + 2 : indent, key });
    } else if (isList && kv) {
      // List item starting with a key (e.g. "- name: listener_0") establishes a sibling level
      stack.push({ indent, key: '_item' });
    }

    // Track static_resources subsections
    if (key === 'listeners' && !rawVal) {
      curSection = 'listeners';
      curCluster = null;
      inEndpoints = false;
    } else if (key === 'clusters' && !rawVal) {
      curSection = 'clusters';
      curListener = null;
      curVhost = null;
      curRoute = null;
      inEndpoints = false;
    }

    // Track admin fields
    if (curTop === 'admin') {
      if (key === 'address' && valStr) admin.address = valStr;
      if (key === 'port_value' && valStr) admin.port = valStr;
      if (key === 'access_log_path' && valStr) admin.accessLogPath = valStr;
    }

    // Track listeners, filter_chains, virtual_hosts, routes
    if (curSection === 'listeners') {
      if (isList && key === 'name' && parentKeys[parentKeys.length - 1] === 'listeners') {
        curListener = {
          name: valStr || `listener_${listeners.length}`,
          address: '',
          port: '',
          filterChains: 0,
          hasTls: false,
          hasTrustedCa: false,
          trustAll: false,
          line: lineNo,
          index: 0,
        };
        listeners.push(curListener);
        curVhost = null;
        curRoute = null;
      } else if (curListener) {
        if (key === 'address' && valStr && !curListener.address && parentKeys.includes('socket_address')) {
          curListener.address = valStr;
        }
        if (key === 'port_value' && valStr && !curListener.port && parentKeys.includes('socket_address')) {
          curListener.port = valStr;
        }
        if (key === 'filters' && parentKeys.includes('filter_chains')) {
          curListener.filterChains += 1;
        }
        if (key === 'transport_socket' || /DownstreamTlsContext/i.test(valStr)) {
          curListener.hasTls = true;
        }
        if (key === 'trusted_ca') curListener.hasTrustedCa = true;
        if (key === 'trust_all' && val === true) curListener.trustAll = true;

        if (isList && key === 'name' && parentKeys.includes('virtual_hosts')) {
          curVhost = { name: valStr, domains: [], line: lineNo };
          curRoute = null;
        } else if (curVhost) {
          if (key === 'domains' && valStr) {
            if (Array.isArray(val)) curVhost.domains.push(...val);
            else curVhost.domains.push(valStr);
          }
          if (isList && !kv && parentKeys.includes('domains') && valStr) {
            curVhost.domains.push(valStr);
          }
          if (key === 'match' && parentKeys.includes('routes')) {
            curRoute = {
              listener: curListener.name,
              virtualHost: curVhost.name,
              domains: curVhost.domains.slice(),
              match: '',
              cluster: '',
              timeout: '',
              line: lineNo,
              index: 0,
            };
            routes.push(curRoute);
          } else if (curRoute) {
            if ((key === 'prefix' || key === 'path' || key === 'safe_regex') && valStr && !curRoute.match) {
              curRoute.match = valStr;
            }
            if (key === 'cluster' && valStr) curRoute.cluster = valStr;
            if (key === 'timeout' && valStr) curRoute.timeout = valStr;
          }
        }
      }
    }

    // Track clusters and endpoints
    if (curSection === 'clusters') {
      if (isList && key === 'name' && parentKeys[parentKeys.length - 1] === 'clusters') {
        curCluster = {
          name: valStr || `cluster_${clusters.length}`,
          type: '',
          connectTimeout: '',
          lbPolicy: '',
          endpoints: [],
          hasTls: false,
          hasTrustedCa: false,
          trustAll: false,
          hasCircuitBreakers: false,
          hasHealthCheck: false,
          line: lineNo,
          index: 0,
        };
        clusters.push(curCluster);
        inEndpoints = false;
        pendingAddr = '';
      } else if (curCluster) {
        if (key === 'type' && valStr && !curCluster.type) curCluster.type = valStr;
        if (key === 'connect_timeout' && valStr) curCluster.connectTimeout = valStr;
        if (key === 'lb_policy' && valStr) curCluster.lbPolicy = valStr;
        if (key === 'load_assignment' || key === 'lb_endpoints') inEndpoints = true;
        if (inEndpoints && key === 'address' && valStr) pendingAddr = valStr;
        if (inEndpoints && key === 'port_value' && valStr) {
          curCluster.endpoints.push(`${pendingAddr || '?'}:${valStr}`);
          pendingAddr = '';
        }
        if (key === 'transport_socket' || /UpstreamTlsContext/i.test(valStr)) curCluster.hasTls = true;
        if (key === 'trusted_ca') curCluster.hasTrustedCa = true;
        if (key === 'trust_all' && val === true) curCluster.trustAll = true;
        if (key === 'circuit_breakers') curCluster.hasCircuitBreakers = true;
        if (key === 'health_checks') curCluster.hasHealthCheck = true;
      }
    }

    // Determine category and section label for row
    let category = 'other';
    let sectionLabel = curTop || 'root';
    let badge = '';
    if (curTop === 'admin') {
      category = 'admin';
      sectionLabel = 'admin';
      badge = 'admin';
    } else if (curSection === 'listeners') {
      category = curRoute ? 'route' : 'listener';
      sectionLabel = curListener ? `listener:${curListener.name}` : 'listeners';
      badge = curRoute ? 'route' : 'listener';
    } else if (curSection === 'clusters') {
      category = 'cluster';
      sectionLabel = curCluster ? `cluster:${curCluster.name}` : 'clusters';
      badge = 'cluster';
    }
    if (/tls|transport_socket|trusted_ca|trust_all|validation_context/i.test(pathStr) || /TlsContext/i.test(valStr)) {
      badge = 'TLS';
    }

    const maskedRaw = maskSecrets(rawLine.trim());
    const maskedVal = maskSecrets(valStr);

    rowIndex += 1;
    const row = {
      index: rowIndex,
      line: lineNo,
      section: sectionLabel,
      directive: pathStr || key || '(item)',
      value: maskedVal,
      category,
      badge,
      raw: maskedRaw,
      findings: [],
      errorCount: 0,
      warningCount: 0,
      attrs: [
        { key: 'Path', value: pathStr || key },
        { key: 'Section', value: sectionLabel },
        { key: 'Category', value: category },
        { key: 'Value', value: maskedVal || '(block)' },
      ],
    };
    rows.push(row);

    if (curTop === 'admin' && admin.index === 0) admin.index = rowIndex;
    if (curListener && curListener.index === 0) curListener.index = rowIndex;
    if (curRoute && curRoute.index === 0) curRoute.index = rowIndex;
    if (curCluster && curCluster.index === 0) curCluster.index = rowIndex;

    // Immediate per-row security checks
    if (key === 'trust_all' && val === true) {
      addFinding('error', 'TLS', 'trust-all-cert-validation', lineNo, sectionLabel, 'trust_all: true disables TLS certificate validation and accepts untrusted certificates.', row);
    }

    // Plaintext auth tokens / secrets detection
    if (key === 'key' && /^(authorization|x-api-key|api-key|x-auth-token)$/i.test(valStr)) {
      pendingHeaderKey = valStr;
      pendingHeaderLine = lineNo;
    } else if (key === 'value' && pendingHeaderKey && (lineNo - pendingHeaderLine) <= 3 && valStr && !/^\$\{/.test(valStr)) {
      addFinding('error', 'Credentials', 'plaintext-auth-token', lineNo, sectionLabel, `Plaintext authentication token detected in header "${pendingHeaderKey}".`, row);
      pendingHeaderKey = '';
    } else if (/^(authorization|api_key|apikey|token|password|secret|inline_string)$/i.test(key) && valStr && !/^\$\{/.test(valStr) && !/^\*+$/.test(valStr)) {
      addFinding('error', 'Credentials', 'plaintext-auth-token', lineNo, sectionLabel, `Plaintext secret or token detected in "${key}".`, row);
    } else if (/^(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/i.test(valStr)) {
      addFinding('error', 'Credentials', 'plaintext-auth-token', lineNo, sectionLabel, 'Plaintext Bearer/Basic authentication credential detected in config value.', row);
    }
  }

  // Post-pass findings
  // 1. Admin bound to 0.0.0.0 or ::
  if (admin.present && /^(0\.0\.0\.0|::)$/.test(admin.address)) {
    const rowRef = rows.find((r) => r.section === 'admin' && r.value === admin.address) || rows.find((r) => r.index === admin.index) || null;
    addFinding('error', 'Admin', 'admin-bound-all-interfaces', admin.line, 'admin', `Envoy admin interface is bound to ${admin.address}:${admin.port || '?'} instead of 127.0.0.1.`, rowRef);
  }

  // 2. Listener missing TLS transport_socket
  for (const l of listeners) {
    if (!l.hasTls) {
      const rowRef = rows.find((r) => r.index === l.index) || null;
      addFinding('warning', 'TLS', 'missing-tls-transport-socket', l.line, `listener:${l.name}`, `Listener "${l.name}" (${l.address || '?'}:${l.port || '?'}) has no TLS transport_socket configured.`, rowRef);
    }
  }

  // 3. Cluster TLS validation, circuit breakers and connect_timeout
  const clusterNames = new Set(clusters.map((c) => c.name));
  for (const c of clusters) {
    const rowRef = rows.find((r) => r.index === c.index) || null;
    if (c.hasTls && !c.hasTrustedCa && !c.trustAll) {
      addFinding('error', 'TLS', 'missing-cert-validation', c.line, `cluster:${c.name}`, `Cluster "${c.name}" enables TLS transport_socket without a trusted_ca validation_context.`, rowRef);
    }
    if (!c.hasCircuitBreakers) {
      addFinding('warning', 'Resilience', 'missing-circuit-breakers', c.line, `cluster:${c.name}`, `Cluster "${c.name}" has no circuit_breakers thresholds configured.`, rowRef);
    }
    if (!c.connectTimeout) {
      addFinding('warning', 'Resilience', 'missing-connect-timeout', c.line, `cluster:${c.name}`, `Cluster "${c.name}" is missing connect_timeout.`, rowRef);
    }
  }

  // 4. Undefined cluster referenced by route
  for (const rt of routes) {
    if (rt.cluster && clusters.length > 0 && !clusterNames.has(rt.cluster)) {
      const rowRef = rows.find((r) => r.index === rt.index) || null;
      addFinding('warning', 'Routing', 'undefined-cluster', rt.line, `listener:${rt.listener}`, `Route "${rt.match || '/'}" references cluster "${rt.cluster}" which is not defined in static_resources.clusters.`, rowRef);
    }
  }

  const endpointCount = clusters.reduce((acc, c) => acc + c.endpoints.length, 0);
  const tlsListenerCount = listeners.filter((l) => l.hasTls).length;
  const findingErrors = findings.filter((f) => f.severity === 'error').length;
  const findingWarnings = findings.filter((f) => f.severity === 'warning').length;

  return {
    title: fileName,
    totalLines: lines.length,
    admin,
    listeners,
    routes,
    clusters,
    rows,
    findings,
    stats: {
      listenerCount: listeners.length,
      tlsListenerCount,
      routeCount: routes.length,
      clusterCount: clusters.length,
      endpointCount,
      rowCount: rows.length,
      findingErrors,
      findingWarnings,
    },
  };
}

function buildAuditMarkdown(entries) {
  const out = ['# Envoy Proxy Security & Resilience Audit', ''];
  let totalErrors = 0;
  let totalWarnings = 0;
  for (const { fileName, parsed } of entries) {
    totalErrors += parsed.stats.findingErrors;
    totalWarnings += parsed.stats.findingWarnings;
    out.push(`## ${fileName}`);
    out.push(`- Listeners: ${parsed.stats.listenerCount} (${parsed.stats.tlsListenerCount} TLS) | Routes: ${parsed.stats.routeCount} | Clusters: ${parsed.stats.clusterCount} | Endpoints: ${parsed.stats.endpointCount}`);
    out.push(`- Admin Interface: ${parsed.admin.present ? `${parsed.admin.address || '?'}:${parsed.admin.port || '?'}` : 'not configured'}`);
    out.push(`- Findings: ${parsed.stats.findingErrors} error(s), ${parsed.stats.findingWarnings} warning(s)`);
    out.push('');
    if (!parsed.findings.length) {
      out.push('_No security or resilience findings detected._', '');
    } else {
      out.push('| Severity | Category | Rule | Line | Section | Finding |');
      out.push('| --- | --- | --- | ---: | --- | --- |');
      for (const f of parsed.findings) {
        out.push(`| ${f.severity.toUpperCase()} | ${f.category} | \`${f.rule}\` | ${f.line} | \`${f.section}\` | ${f.message.replace(/\|/g, '\\|')} |`);
      }
      out.push('');
    }
  }
  out.splice(2, 0, `**Files audited:** ${entries.length} · **Total errors:** ${totalErrors} · **Total warnings:** ${totalWarnings}`, '');
  return out.join('\n');
}

function buildDiffMarkdown(leftName, left, rightName, right) {
  const out = [`# Envoy Config Diff: ${leftName} vs ${rightName}`, ''];
  const diffSet = (label, aList, bList) => {
    const aSet = new Set(aList);
    const bSet = new Set(bList);
    const added = bList.filter((x) => !aSet.has(x));
    const removed = aList.filter((x) => !bSet.has(x));
    out.push(`## ${label}`);
    if (!added.length && !removed.length) {
      out.push('_No changes._', '');
      return;
    }
    for (const x of added) out.push(`- **Added:** \`${x}\``);
    for (const x of removed) out.push(`- **Removed:** \`${x}\``);
    out.push('');
  };

  diffSet('Listener Changes', left.listeners.map((l) => `${l.name} (${l.address}:${l.port} tls=${l.hasTls})`), right.listeners.map((l) => `${l.name} (${l.address}:${l.port} tls=${l.hasTls})`));
  diffSet('Route Changes', left.routes.map((r) => `${r.listener}/${r.virtualHost} ${r.match} -> ${r.cluster}`), right.routes.map((r) => `${r.listener}/${r.virtualHost} ${r.match} -> ${r.cluster}`));
  diffSet('Cluster Changes', left.clusters.map((c) => `${c.name} (${c.type} eps=${c.endpoints.join(',') || 'none'})`), right.clusters.map((c) => `${c.name} (${c.type} eps=${c.endpoints.join(',') || 'none'})`));
  diffSet('Security Finding Changes', left.findings.map((f) => `${f.severity}:${f.rule} @ ${f.section}`), right.findings.map((f) => `${f.severity}:${f.rule} @ ${f.section}`));
  return out.join('\n');
}

function safeId(s) {
  return String(s || 'node').replace(/[^a-zA-Z0-9_]/g, '_');
}

function buildClusterMapMermaid(parsed) {
  const lines = ['flowchart LR'];
  for (const l of parsed.listeners) {
    const lId = `ls_${safeId(l.name)}`;
    lines.push(`  ${lId}["Listener: ${l.name} (${l.address || '?'}:${l.port || '?'}${l.hasTls ? ' TLS' : ''})"]`);
  }
  for (const rt of parsed.routes) {
    const lId = `ls_${safeId(rt.listener)}`;
    const cId = `cl_${safeId(rt.cluster || 'unknown')}`;
    const label = `${rt.virtualHost || 'vhost'}: ${rt.match || '/'}`;
    lines.push(`  ${lId} -->|"${label.replace(/"/g, "'")}"| ${cId}`);
  }
  for (const c of parsed.clusters) {
    const cId = `cl_${safeId(c.name)}`;
    lines.push(`  ${cId}["Cluster: ${c.name} (${c.type || 'STATIC'})"]`);
    for (const ep of c.endpoints) {
      const eId = `ep_${safeId(`${c.name}_${ep}`)}`;
      lines.push(`  ${eId}["Endpoint: ${ep}"]`);
      lines.push(`  ${cId} --> ${eId}`);
    }
  }
  return lines.join('\n');
}

function buildInventoryCsv(parsed) {
  const escCsv = (v) => {
    const s = String(v == null ? '' : v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const out = ['kind,name,address_or_match,target_or_endpoints,tls,resilience,line'];
  if (parsed.admin.present) {
    out.push(['admin', 'admin', `${parsed.admin.address}:${parsed.admin.port}`, parsed.admin.accessLogPath || '', 'false', '', parsed.admin.line].map(escCsv).join(','));
  }
  for (const l of parsed.listeners) {
    out.push(['listener', l.name, `${l.address}:${l.port}`, `${l.filterChains} chains`, l.hasTls ? 'true' : 'false', '', l.line].map(escCsv).join(','));
  }
  for (const rt of parsed.routes) {
    out.push(['route', `${rt.listener}/${rt.virtualHost}`, rt.match || '/', rt.cluster, '', rt.timeout ? `timeout=${rt.timeout}` : '', rt.line].map(escCsv).join(','));
  }
  for (const c of parsed.clusters) {
    const res = [c.connectTimeout ? `timeout=${c.connectTimeout}` : 'no-timeout', c.hasCircuitBreakers ? 'cb' : 'no-cb'].join('; ');
    out.push(['cluster', c.name, c.type || 'STATIC', c.endpoints.join(' '), c.hasTls ? 'true' : 'false', res, c.line].map(escCsv).join(','));
  }
  return out.join('\n') + '\n';
}

function buildClusterMapSummaryMarkdown(parsed, fileName = 'envoy.yaml') {
  const out = [
    `# Envoy Listener & Cluster Map: ${fileName}`,
    '',
    `- **Listeners:** ${parsed.stats.listenerCount} (${parsed.stats.tlsListenerCount} with TLS)`,
    `- **HTTP Routes:** ${parsed.stats.routeCount}`,
    `- **Clusters:** ${parsed.stats.clusterCount}`,
    `- **Endpoints:** ${parsed.stats.endpointCount}`,
    `- **Admin Interface:** ${parsed.admin.present ? `${parsed.admin.address || '?'}:${parsed.admin.port || '?'}` : 'not configured'}`,
    `- **Security Findings:** ${parsed.stats.findingErrors} error(s), ${parsed.stats.findingWarnings} warning(s)`,
    '',
    '## Listener-to-Cluster Graph',
    '',
    '```mermaid',
    buildClusterMapMermaid(parsed),
    '```',
    '',
  ];
  return out.join('\n');
}

module.exports = {
  parseEnvoy,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildClusterMapMermaid,
  buildInventoryCsv,
  buildClusterMapSummaryMarkdown,
  maskSecrets,
};
