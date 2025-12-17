# Deployments

This repository ships a few **ready-to-run** deployment options so you can evaluate AgentField quickly:

## Pick one

### 1) Docker Compose (fastest local evaluation)

Best if you want to try the UI + execute API in minutes on a laptop.

- Docs: `deployments/docker/README.md`

### 2) Helm (recommended for Kubernetes)

Best for production-like installs and customization via `values.yaml`.

- Chart + docs: `deployments/helm/agentfield`

### 3) Kustomize (plain Kubernetes YAML)

Best if you want transparent manifests and minimal tooling.

- Docs: `deployments/kubernetes/README.md`

