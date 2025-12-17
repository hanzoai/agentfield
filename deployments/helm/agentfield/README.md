# AgentField Helm Chart

This chart installs the AgentField **control plane** and (optionally) an example **demo agent** to validate end-to-end registration + execution in a Kubernetes cluster.

## Quick Start

### Local storage (SQLite/BoltDB in a PVC)

```bash
helm upgrade --install agentfield deployments/helm/agentfield
kubectl port-forward svc/agentfield-control-plane 8080:8080
open http://localhost:8080/ui/
```

### With a demo agent (recommended for evaluation)

Build an image for the demo agent and make it available to your cluster.

```bash
docker build -f deployments/docker/Dockerfile.demo-go-agent -t agentfield-demo-go-agent:local .
```

Then install with the demo agent enabled:

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  --set demoAgent.enabled=true
```

Test an execution after port-forwarding:

```bash
curl -X POST http://localhost:8080/api/v1/execute/demo-go-agent.demo_echo \
  -H "Content-Type: application/json" \
  -d '{"input": {"message": "Hello!"}}'
```

### With PostgreSQL (pgvector)

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  --set postgres.enabled=true \
  --set controlPlane.storage.mode=postgres
```

## Demo Python agent (no custom image)

This option deploys a small Python agent that installs the AgentField Python SDK from PyPI at startup (intended for evaluation).

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  --set postgres.enabled=true \
  --set controlPlane.storage.mode=postgres \
  --set demoPythonAgent.enabled=true
```

Then port-forward and call through the control plane:

```bash
kubectl port-forward svc/agentfield-control-plane 8080:8080
curl -X POST http://localhost:8080/api/v1/execute/demo-python-agent.hello \
  -H "Content-Type: application/json" \
  -d '{"input":{"name":"World"}}'
```

To check VCs, copy the `run_id` from the response and fetch:

```bash
curl http://localhost:8080/api/v1/did/workflow/<RUN_ID>/vc-chain | head -c 1200
```

## Authentication (optional)

To require an API key:

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  --set apiAuth.enabled=true \
  --set apiAuth.apiKey='change-me'
```

When enabled, agent nodes must send `Authorization: Bearer <apiKey>` (the Go demo agent will use `AGENTFIELD_TOKEN` automatically when deployed by this chart).

## Configuration Notes

- The control plane stores local state under `AGENTFIELD_HOME` (default: `/data`). For Kubernetes, the chart mounts a PVC at that path by default.
- The chart defaults `AGENTFIELD_CONFIG_FILE=/dev/null` so the control plane uses built-in defaults + environment variables. If you want to use a custom YAML config, mount it and set `AGENTFIELD_CONFIG_FILE` accordingly.
- Admin gRPC listens on `(AGENTFIELD_PORT + 100)` and is exposed via the Service on `grpc` (default `8180` when port is `8080`).
