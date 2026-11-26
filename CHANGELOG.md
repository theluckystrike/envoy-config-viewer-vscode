# Changelog

## 0.1.0

- First release: `envoy.yaml`, `envoy.yml`, `*.envoy.yaml` and `envoy-config.yaml` in a read-only offline viewer, parsed locally with plain JavaScript and zero Envoy daemon, shell or cloud calls.
- Listeners, filter chains, HTTP route virtual hosts, clusters/endpoints and admin interface explorer with static security and resilience findings (`admin` on `0.0.0.0`, missing TLS `transport_socket`, `trust_all` or missing cert validation, missing circuit breakers/timeouts, plaintext auth tokens).
- Zovo Pro tools with 1 free try each: Markdown Envoy security and resilience audit, two-file YAML config diff, and Mermaid listener-to-cluster graph plus Markdown and CSV inventory export. Get Zovo Pro first shows what Pro includes and the tries left, in an editor tab.
