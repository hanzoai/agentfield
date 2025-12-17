# Helm (Kubernetes)

This chart installs the AgentField control plane and optional demo agents.

## Quick start (recommended)

Install with PostgreSQL and the demo Python agent (no custom image required):

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  -n agentfield --create-namespace \
  --set postgres.enabled=true \
  --set controlPlane.storage.mode=postgres \
  --set demoPythonAgent.enabled=true
```

Port-forward the UI/API:

```bash
kubectl -n agentfield port-forward svc/agentfield-control-plane 8080:8080
```

Open:
- `http://localhost:8080/ui/`

Execute via the control plane:

```bash
curl -X POST http://localhost:8080/api/v1/execute/demo-python-agent.hello \
  -H "Content-Type: application/json" \
  -d '{"input":{"name":"World"}}'
```

Check VCs:

```bash
resp=$(curl -s -X POST http://localhost:8080/api/v1/execute/demo-python-agent.hello \
  -H "Content-Type: application/json" \
  -d '{"input":{"name":"VC"}}')
run_id=$(echo "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["run_id"])')
curl -s http://localhost:8080/api/v1/did/workflow/$run_id/vc-chain | head -c 1200
```

## Options

### Local storage (SQLite/BoltDB)

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  -n agentfield --create-namespace \
  --set controlPlane.storage.mode=local
```

### Go demo agent (requires a custom image)

The Go demo agent is useful, but you must build/push/load an image that your cluster can pull.

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  -n agentfield --create-namespace \
  --set demoAgent.enabled=true
```

## Authentication (optional)

```bash
helm upgrade --install agentfield deployments/helm/agentfield \
  -n agentfield --create-namespace \
  --set apiAuth.enabled=true \
  --set apiAuth.apiKey='change-me'
```

## Notes

- The chart defaults `AGENTFIELD_CONFIG_FILE=/dev/null` so the control plane uses built-in defaults + environment variables.
- Admin gRPC listens on `(AGENTFIELD_PORT + 100)` and is exposed via the Service port named `grpc`.
