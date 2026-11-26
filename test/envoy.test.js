'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parseEnvoy,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildClusterMapMermaid,
  buildInventoryCsv,
  buildClusterMapSummaryMarkdown,
} = require('../src/envoy');
const { EnvoyViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

test('parses sample envoy.yaml with admin 0.0.0.0, missing TLS, trust_all, missing circuit breakers/timeout and plaintext auth token', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'envoy.yaml'));
  const parsed = parseEnvoy(buf, 'envoy.yaml');
  assert.equal(parsed.admin.present, true);
  assert.equal(parsed.admin.address, '0.0.0.0');
  assert.equal(parsed.stats.listenerCount, 1);
  assert.equal(parsed.stats.routeCount, 2);
  assert.equal(parsed.stats.clusterCount, 1);
  assert.equal(parsed.stats.endpointCount, 1);
  const rules = new Set(parsed.findings.map((f) => f.rule));
  assert.ok(rules.has('admin-bound-all-interfaces'));
  assert.ok(rules.has('missing-tls-transport-socket'));
  assert.ok(rules.has('trust-all-cert-validation'));
  assert.ok(rules.has('missing-circuit-breakers'));
  assert.ok(rules.has('missing-connect-timeout'));
  assert.ok(rules.has('plaintext-auth-token'));
  assert.ok(rules.has('undefined-cluster'));
  // Ensure plaintext bearer token is masked in row output
  assert.ok(!parsed.rows.some((r) => r.raw.includes('example_demo_token_12345')));
});

test('parses hardened.envoy.yaml with zero security findings', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'hardened.envoy.yaml'));
  const parsed = parseEnvoy(buf, 'hardened.envoy.yaml');
  assert.equal(parsed.admin.address, '127.0.0.1');
  assert.equal(parsed.stats.listenerCount, 1);
  assert.equal(parsed.stats.tlsListenerCount, 1);
  assert.equal(parsed.stats.clusterCount, 1);
  assert.equal(parsed.findings.length, 0);
});

test('EnvoyViewModel filters by category, findings and text', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'envoy.yaml'));
  const parsed = parseEnvoy(buf, 'envoy.yaml');
  const vm = new EnvoyViewModel(parsed, 'envoy.yaml', buf.length);
  assert.ok(vm.setFilter({ text: '', kind: 'cluster' }) >= 5);
  assert.ok(vm.setFilter({ text: '', kind: 'findings' }) >= 4);
  assert.ok(vm.setFilter({ text: 'trust_all', kind: '' }) >= 1);
  const det = vm.detail(1);
  assert.ok(det && det.section === 'admin');
});

test('Pro report builders produce security audit, config diff, Mermaid cluster map and CSV inventory', () => {
  const baseline = parseEnvoy(fs.readFileSync(path.join(__dirname, '..', 'samples', 'envoy.yaml')), 'envoy.yaml');
  const target = parseEnvoy(fs.readFileSync(path.join(__dirname, '..', 'samples', 'hardened.envoy.yaml')), 'hardened.envoy.yaml');
  const audit = buildAuditMarkdown([{ fileName: 'envoy.yaml', parsed: baseline }]);
  assert.match(audit, /Envoy Proxy Security & Resilience Audit/);
  assert.match(audit, /admin-bound-all-interfaces/);
  const diff = buildDiffMarkdown('envoy.yaml', baseline, 'hardened.envoy.yaml', target);
  assert.match(diff, /Listener Changes/);
  assert.match(diff, /Security Finding Changes/);
  const mermaid = buildClusterMapMermaid(baseline);
  assert.match(mermaid, /flowchart LR/);
  assert.match(mermaid, /ls_ingress_http/);
  const csv = buildInventoryCsv(baseline);
  assert.match(csv, /^kind,name,address_or_match,target_or_endpoints,tls,resilience,line/);
  const md = buildClusterMapSummaryMarkdown(baseline, 'envoy.yaml');
  assert.match(md, /```mermaid/);
});

test('editorHtml enforces strict CSP with nonce and no unsafe-inline', () => {
  const html = editorHtml({ cspSource: 'vscode-webview://test', script: 'v.js', styleUri: 'v.css', title: 'envoy.yaml', nonce: 'envy123' });
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-envy123'/);
  assert.doesNotMatch(csp('vscode-webview://test', 'envy123'), /unsafe-inline/);
});
