# AgentField Docker Deployments

This directory contains reference Dockerfiles and a Compose stack for local development.

## Images

- `Dockerfile.control-plane` – builds the Go control plane and embeds the web UI.
- `Dockerfile.python-agent` – base image for Python agents that bundles the SDK.
- `Dockerfile.go-agent` – base image for Go agents with the Go SDK pre-fetched.

## Local Stack

```bash
cd deployments/docker
docker compose up --build
```

The stack exposes:

- Control plane: `http://localhost:8080`
- Demo agent (Go): `http://localhost:8001` (auto-registers to the control plane)

It also provisions PostgreSQL (pgvector) for durable storage.

## Validate the execution path (control plane -> agent)

Once running, hit the **control plane execute API** (the control plane will call the agent node):

```bash
curl -X POST http://localhost:8080/api/v1/execute/demo-go-agent.demo_echo \
  -H "Content-Type: application/json" \
  -d '{"input": {"message": "Hello!"}}'
```

## Python hello world (optional)

Enable the Dockerized Python demo agent (deterministic; no LLM keys required):

```bash
cd deployments/docker
docker compose --profile python-demo up --build
```

Then call it through the control plane:

```bash
curl -X POST http://localhost:8080/api/v1/execute/demo-python-agent.hello \
  -H "Content-Type: application/json" \
  -d '{"input": {"name": "World"}}'
```

### Verify Verifiable Credentials (VCs)

The Python SDK will automatically POST execution VC material back to the control plane.

1) Capture the `run_id` from the execute response:

```bash
resp=$(curl -s -X POST http://localhost:8080/api/v1/execute/demo-python-agent.hello \
  -H "Content-Type: application/json" \
  -d '{"input":{"name":"VC"}}')
echo "$resp"
run_id=$(echo "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["run_id"])')
```

2) Fetch the VC chain for the workflow:

```bash
curl -s http://localhost:8080/api/v1/did/workflow/$run_id/vc-chain | head -c 1200
```

### Default PostgreSQL credentials (for evaluation)

- User: `agentfield`
- Password: `agentfield`
- Database: `agentfield`

Control plane uses:

- `AGENTFIELD_STORAGE_MODE=postgres`
- `AGENTFIELD_POSTGRES_URL=postgres://agentfield:agentfield@postgres:5432/agentfield?sslmode=disable`

### Callback/Public URL in Docker

The control plane needs to be able to reach agent nodes at the URL they register.

- If the agent is running **in the same Compose stack**, use the service DNS name, e.g. `AGENT_PUBLIC_URL=http://demo-go-agent:8001`.
- If the agent is running **on your host** and the control plane is in Docker, set:
  - Python agents: `AGENT_CALLBACK_URL=http://host.docker.internal:<port>`
  - Go agents: `AGENT_PUBLIC_URL=http://host.docker.internal:<port>`

Override configuration by editing `docker-compose.yml` or passing environment variables when running Compose.
