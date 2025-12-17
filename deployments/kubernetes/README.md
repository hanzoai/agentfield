# Kubernetes Manifests (Kustomize)

This directory contains reference Kubernetes manifests for evaluating AgentField without Helm.

If you prefer Helm, use `deployments/helm/agentfield` instead.

## Variants

- `deployments/kubernetes/base` – Control plane with local storage (SQLite/BoltDB) persisted in a PVC.
- `deployments/kubernetes/overlays/local-demo` – Base + demo Go agent (validates registration + execution).
- `deployments/kubernetes/overlays/python-demo` – Base + demo Python agent (validates VC generation via Python SDK).
- `deployments/kubernetes/overlays/postgres-demo` – Base + pgvector PostgreSQL + demo Go agent.

## Quick Start (local cluster)

### 1) Create a namespace (optional)

```bash
kubectl create namespace agentfield --dry-run=client -o yaml | kubectl apply -f -
kubectl config set-context --current --namespace=agentfield
```

### 2) Apply an overlay

Local storage + demo agent:

```bash
kubectl apply -k deployments/kubernetes/overlays/local-demo
```

Python demo agent (requires loading local images into your cluster, see below):

```bash
kubectl apply -k deployments/kubernetes/overlays/python-demo
```

Postgres + demo agent:

```bash
kubectl apply -k deployments/kubernetes/overlays/postgres-demo
```

### 3) Port-forward the UI

```bash
kubectl port-forward svc/agentfield-control-plane 8080:8080
open http://localhost:8080
```

Notes:
- `kubectl port-forward` must keep running in that terminal; if you stop it, `http://localhost:8080` will not respond.
- If your browser shows a blank page, open the UI directly at `http://localhost:8080/ui/`.
- Quick sanity check from a terminal: `curl -s http://localhost:8080/api/v1/health`.

### 4) Test an execution

```bash
curl -X POST http://localhost:8080/api/v1/execute/demo-go-agent.demo_echo \
  -H "Content-Type: application/json" \
  -d '{"input": {"message": "Hello!"}}'
```

## Demo Python agent on minikube

This overlay uses local images:
- `agentfield-control-plane:local`
- `agentfield-demo-python-agent:local`

Build them and load into minikube:

```bash
docker build -f deployments/docker/Dockerfile.control-plane -t agentfield-control-plane:local .
docker build -f deployments/docker/Dockerfile.demo-python-agent -t agentfield-demo-python-agent:local .
minikube image load agentfield-control-plane:local
minikube image load agentfield-demo-python-agent:local
kubectl apply -k deployments/kubernetes/overlays/python-demo
```

Then execute (copy `run_id` from the response) and fetch the VC chain:

```bash
resp=$(curl -s -X POST http://localhost:8080/api/v1/execute/demo-python-agent.hello \
  -H "Content-Type: application/json" \
  -d '{"input":{"name":"VC"}}')
echo "$resp"
run_id=$(echo "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["run_id"])')
curl -s http://localhost:8080/api/v1/did/workflow/$run_id/vc-chain | head -c 1200
```

## Notes

- The demo agent image is referenced as `agentfield-demo-go-agent:local`. Build/push/load it for your cluster:
  - Dockerfile: `deployments/docker/Dockerfile.demo-go-agent`
- For Kubernetes agent nodes, set their registered URL to a `Service` DNS name (`AGENT_PUBLIC_URL` / `AGENT_CALLBACK_URL`), not `localhost`.
