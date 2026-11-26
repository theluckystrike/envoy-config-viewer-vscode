/* global acquireVsCodeApi */
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');

  let state = {
    name: '',
    summary: null,
    pageSize: 100,
    page: 0,
    total: 0,
    rows: [],
    selected: null,
    tab: 'entries',
    req: 0,
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function post(msg) {
    state.req += 1;
    vscode.postMessage({ ...msg, req: state.req });
  }

  function fmtSize(n) {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function renderShell() {
    const s = state.summary;
    const errChip = s.findingErrors > 0 ? `<span class="chip bad"><b>Errors:</b> ${s.findingErrors}</span>` : '<span class="chip"><b>Errors:</b> 0</span>';
    const warnChip = s.findingWarnings > 0 ? `<span class="chip warn"><b>Warnings:</b> ${s.findingWarnings}</span>` : '';
    const adminText = s.admin && s.admin.present ? `${s.admin.address || '?'}:${s.admin.port || '?'}` : 'none';

    app.innerHTML = `
      <div class="top">
        <div class="title">
          <span class="name">${esc(s.title || state.name)}</span>
          <span class="kind">Envoy YAML · ${s.totalLines} lines · ${fmtSize(s.fileSize)} · 100% offline (no daemon or network calls)</span>
        </div>
        <div class="summary">
          <span class="chip"><b>Listeners:</b> ${s.listenerCount} (${s.tlsListenerCount} TLS)</span>
          <span class="chip"><b>Routes:</b> ${s.routeCount}</span>
          <span class="chip"><b>Clusters:</b> ${s.clusterCount}</span>
          <span class="chip"><b>Endpoints:</b> ${s.endpointCount}</span>
          <span class="chip"><b>Admin:</b> ${esc(adminText)}</span>
          ${errChip}${warnChip}
        </div>
        <div class="toolbar">
          <input id="q" type="search" placeholder="Filter by listener, virtual host, route, cluster, endpoint, TLS..." />
          <select id="kindFilter">
            <option value="">All entries</option>
            <option value="listener">Listeners</option>
            <option value="route">HTTP Routes</option>
            <option value="cluster">Clusters &amp; Endpoints</option>
            <option value="admin">Admin</option>
            <option value="tls">TLS &amp; Transport</option>
            <option value="findings">With Findings</option>
          </select>
          <button id="filterBtn" type="button">Filter</button>
          <span class="sep"></span>
          <div id="protools"></div>
        </div>
        <div class="tabs">
          <button class="tab on" data-tab="entries" type="button">Config Entries (${s.rowCount})</button>
          <button class="tab" data-tab="routes" type="button">Listeners &amp; Routes (${(s.listeners || []).length + (s.routes || []).length})</button>
          <button class="tab" data-tab="clusters" type="button">Clusters &amp; Endpoints (${(s.clusters || []).length})</button>
          <button class="tab" data-tab="findings" type="button">Findings (${(s.findings || []).length})</button>
        </div>
        <div id="hint" class="hint"></div>
      </div>
      <div class="main">
        <div id="leftPane" class="tablewrap"></div>
        <div id="detail" class="detail"><p class="muted">Select an entry, listener, route or cluster to inspect its Envoy configuration details.</p></div>
      </div>
      <div class="pager">
        <button id="prev" type="button">Prev</button>
        <span id="pageInfo"></span>
        <button id="next" type="button">Next</button>
      </div>
    `;

    const q = document.getElementById('q');
    const kSel = document.getElementById('kindFilter');
    const runFilter = () => {
      state.page = 0;
      post({ type: 'filter', filter: { text: q.value, kind: kSel.value } });
    };
    document.getElementById('filterBtn').addEventListener('click', runFilter);
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') runFilter(); });
    kSel.addEventListener('change', runFilter);

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state.tab = btn.dataset.tab;
        renderPane();
      });
    });

    document.getElementById('prev').addEventListener('click', () => {
      if (state.page > 0) { state.page -= 1; loadPage(); }
    });
    document.getElementById('next').addEventListener('click', () => {
      if ((state.page + 1) * state.pageSize < state.total) { state.page += 1; loadPage(); }
    });
  }

  function loadPage() {
    post({ type: 'page', from: state.page * state.pageSize, n: state.pageSize });
  }

  function bindRowClicks(left) {
    left.querySelectorAll('tbody tr[data-idx]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const idx = Number(tr.dataset.idx);
        state.selected = idx;
        left.querySelectorAll('tbody tr').forEach((row) => row.classList.toggle('sel', Number(row.dataset.idx) === idx));
        post({ type: 'detail', index: idx });
      });
    });
  }

  function renderPane() {
    const left = document.getElementById('leftPane');
    const pager = document.querySelector('.pager');
    const s = state.summary;

    if (state.tab === 'routes') {
      pager.style.display = 'none';
      const lRows = (s.listeners || []).map((l) => `<tr data-idx="${l.index}"${state.selected === l.index ? ' class="sel"' : ''}>
        <td class="num">${l.line}</td>
        <td><strong>LISTENER</strong></td>
        <td><code>${esc(l.name)}</code></td>
        <td><code>${esc(`${l.address || '?'}:${l.port || '?'}`)}</code></td>
        <td class="${l.hasTls ? 'ok' : 'warn-text'}">${l.hasTls ? 'TLS' : 'Plain'}</td>
        <td>${l.filterChains} filter chain(s)</td>
      </tr>`).join('');
      const rRows = (s.routes || []).map((r) => `<tr data-idx="${r.index}"${state.selected === r.index ? ' class="sel"' : ''}>
        <td class="num">${r.line}</td>
        <td><strong>ROUTE</strong></td>
        <td><code>${esc(`${r.listener} / ${r.virtualHost}`)}</code></td>
        <td><code>${esc(r.match || '/')}</code></td>
        <td><code>${esc(r.cluster || '-')}</code></td>
        <td>${r.timeout ? `timeout=${esc(r.timeout)}` : '-'}</td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th class="num">Line</th><th>Kind</th><th>Name / VHost</th><th>Address / Match</th><th>TLS / Target</th><th>Details</th></tr></thead>
        <tbody>${(lRows + rRows) || '<tr><td colspan="6" class="muted">No listeners or HTTP routes found.</td></tr>'}</tbody>
      </table>`;
      bindRowClicks(left);
      return;
    }

    if (state.tab === 'clusters') {
      pager.style.display = 'none';
      const cRows = (s.clusters || []).map((c) => `<tr data-idx="${c.index}"${state.selected === c.index ? ' class="sel"' : ''}>
        <td class="num">${c.line}</td>
        <td><code>${esc(c.name)}</code></td>
        <td>${esc(c.type || 'STATIC')}</td>
        <td><code>${esc((c.endpoints || []).join(', ') || '-')}</code></td>
        <td class="${c.trustAll || (c.hasTls && !c.hasTrustedCa) ? 'bad' : (c.hasTls ? 'ok' : '')}">${c.hasTls ? (c.trustAll ? 'TLS (trust_all)' : (c.hasTrustedCa ? 'TLS (CA)' : 'TLS (no CA)')) : 'Plain'}</td>
        <td>${c.connectTimeout ? `t=${esc(c.connectTimeout)}` : '<span class="warn-text">no timeout</span>'} · ${c.hasCircuitBreakers ? 'CB' : '<span class="warn-text">no CB</span>'}</td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th class="num">Line</th><th>Cluster</th><th>Type</th><th>Endpoints</th><th>TLS Posture</th><th>Resilience</th></tr></thead>
        <tbody>${cRows || '<tr><td colspan="6" class="muted">No clusters found.</td></tr>'}</tbody>
      </table>`;
      bindRowClicks(left);
      return;
    }

    if (state.tab === 'findings') {
      pager.style.display = 'none';
      const fRows = (s.findings || []).map((f) => `<tr>
        <td class="${f.severity === 'error' ? 'bad' : 'warn-text'}"><strong>${esc(f.severity.toUpperCase())}</strong></td>
        <td>${esc(f.category)}</td>
        <td><code>${esc(f.rule)}</code></td>
        <td class="num">${f.line}</td>
        <td><code>${esc(f.section)}</code></td>
        <td>${esc(f.message)}</td>
      </tr>`).join('');
      left.innerHTML = fRows
        ? `<table id="grid"><thead><tr><th>Severity</th><th>Category</th><th>Rule</th><th class="num">Line</th><th>Section</th><th>Finding</th></tr></thead><tbody>${fRows}</tbody></table>`
        : '<p class="muted" style="padding:12px;">No Envoy security or resilience findings.</p>';
      return;
    }

    pager.style.display = 'flex';
    const body = state.rows.map((r) => {
      const sel = state.selected === r.index ? ' class="sel"' : '';
      const badge = r.badge ? `<span class="badge-muted">${esc(r.badge)}</span>` : '';
      const statusCls = r.errorCount > 0 ? 'bad' : (r.warningCount > 0 ? 'warn-text' : '');
      return `<tr data-idx="${r.index}"${sel}>
        <td class="num">${r.line}</td>
        <td><code>${esc(r.section)}</code></td>
        <td class="${statusCls}"><strong>${esc(r.directive)}</strong>${badge}</td>
        <td><code>${esc(r.value || '-')}</code></td>
      </tr>`;
    }).join('');
    left.innerHTML = `<table id="grid">
      <thead><tr><th class="num">Line</th><th>Section</th><th>Key Path</th><th>Value</th></tr></thead>
      <tbody>${body || '<tr><td colspan="4" class="muted">No matching entries.</td></tr>'}</tbody>
    </table>`;
    bindRowClicks(left);

    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    document.getElementById('pageInfo').textContent = `Page ${state.page + 1} of ${pages} (${state.total} entries)`;
    document.getElementById('prev').disabled = state.page <= 0;
    document.getElementById('next').disabled = (state.page + 1) * state.pageSize >= state.total;
  }

  function renderDetail(d) {
    const el = document.getElementById('detail');
    if (!d) {
      el.innerHTML = '<p class="muted">No entry selected.</p>';
      return;
    }
    const attrRows = (d.attrs || []).map((a) => `<tr><td><strong>${esc(a.key)}</strong></td><td><code>${esc(a.value)}</code></td></tr>`).join('');
    const findHtml = (d.findings && d.findings.length)
      ? '<div class="attr-head"><strong>Findings</strong></div>' + d.findings.map((f) => `<div class="error" style="margin:4px 0;padding:6px 10px;"><strong>${esc(f.rule)}</strong>: ${esc(f.message)}</div>`).join('')
      : '';
    const rawHtml = d.raw ? `<div class="attr-head"><strong>Raw Line</strong></div><pre class="trace">${esc(d.raw)}</pre>` : '';

    el.innerHTML = `
      <div class="dhead"><strong>Line ${d.line}: ${esc(d.section)}</strong><span>${esc(d.badge || '')}</span></div>
      <table class="splits"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${attrRows}</tbody></table>
      ${findHtml}${rawHtml}
    `;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (!m || typeof m !== 'object') return;
    switch (m.type) {
      case 'init':
        if (m.error) {
          app.innerHTML = `<div class="error"><strong>Could not open ${esc(m.name)}</strong><p>${esc(m.error)}</p></div>`;
          return;
        }
        state.name = m.name;
        state.summary = m.summary;
        state.pageSize = m.pageSize || 100;
        state.page = 0;
        renderShell();
        loadPage();
        return;
      case 'pageResult':
        state.total = m.total;
        state.rows = m.rows || [];
        renderPane();
        if (state.rows.length && state.selected == null) {
          state.selected = state.rows[0].index;
          post({ type: 'detail', index: state.selected });
        }
        return;
      case 'filterResult':
        state.total = m.count;
        document.getElementById('hint').textContent = m.count < m.total ? `Showing ${m.count} of ${m.total} entries.` : '';
        loadPage();
        return;
      case 'detailResult':
        renderDetail(m.detail);
        return;
      case 'zovoAlso': {
        const anchor = m.anchor && document.getElementById(m.anchor);
        if (anchor && m.html) {
          const old = document.querySelector('.zovo-also');
          if (old) old.remove();
          anchor.insertAdjacentHTML('afterend', m.html);
        }
        return;
      }
      case 'hint':
        if (document.getElementById('hint')) document.getElementById('hint').textContent = m.text || '';
        return;
      default:
    }
  });

  post({ type: 'ready' });
})();
