'use strict';
// View model for Envoy Proxy Config Viewer: pagination, filtering by category/text, listeners, routes, clusters and findings.

class EnvoyViewModel {
  constructor(parsed, name, fileSize) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.filter = { text: '', kind: '' };
    this.filtered = parsed.rows.slice();
  }

  summary() {
    const p = this.parsed;
    const s = p.stats;
    return {
      name: this.name,
      fileSize: this.fileSize,
      title: p.title,
      totalLines: p.totalLines,
      admin: p.admin,
      listenerCount: s.listenerCount,
      tlsListenerCount: s.tlsListenerCount,
      routeCount: s.routeCount,
      clusterCount: s.clusterCount,
      endpointCount: s.endpointCount,
      rowCount: s.rowCount,
      findingErrors: s.findingErrors,
      findingWarnings: s.findingWarnings,
      listeners: p.listeners,
      routes: p.routes,
      clusters: p.clusters,
      findings: p.findings,
    };
  }

  totalCount() {
    return this.parsed.rows.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const kind = f && typeof f.kind === 'string' ? f.kind.trim() : '';
    this.filter = { text, kind };
    this.filtered = this.parsed.rows.filter((r) => {
      if (kind === 'listener' && r.category !== 'listener') return false;
      if (kind === 'route' && r.category !== 'route') return false;
      if (kind === 'cluster' && r.category !== 'cluster') return false;
      if (kind === 'admin' && r.category !== 'admin') return false;
      if (kind === 'tls' && r.badge !== 'TLS' && !/tls|transport_socket|trusted_ca|trust_all/i.test(r.directive)) return false;
      if (kind === 'findings' && !r.errorCount && !r.warningCount) return false;
      if (text) {
        const hay = `${r.section} ${r.directive} ${r.value} ${r.badge} ${r.raw}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((r) => ({
      index: r.index,
      line: r.line,
      section: r.section,
      directive: r.directive,
      value: r.value,
      category: r.category,
      badge: r.badge,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
    }));
  }

  detail(index) {
    const r = this.parsed.rows.find((x) => x.index === index) || this.parsed.rows[0] || null;
    if (!r) return null;
    return {
      index: r.index,
      line: r.line,
      section: r.section,
      directive: r.directive,
      value: r.value,
      badge: r.badge,
      raw: r.raw,
      findings: r.findings,
      attrs: r.attrs,
    };
  }
}

module.exports = { EnvoyViewModel };
