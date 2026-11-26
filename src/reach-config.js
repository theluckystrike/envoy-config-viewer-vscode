'use strict';
module.exports = {
  prefix: 'zovoEnvoy',
  triesKey: 'zovoEnvoy.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditEnvoy', title: 'Audit Envoy security and resilience', command: 'zovoEnvoy.auditEnvoy' },
    { id: 'diffConfigs', title: 'Compare two Envoy YAML configs', command: 'zovoEnvoy.diffConfigs' },
    { id: 'exportClusterMap', title: 'Export Mermaid cluster map and inventory', command: 'zovoEnvoy.exportClusterMap' },
  ],
};
