# Deployments

This repository ships a few **ready-to-run** deployment options so you can evaluate AgentField quickly.

**Full deployment guides:** [agentfield.ai/guides/deployment/overview](https://agentfield.ai/guides/deployment/overview)

## Pick one

### 1) Docker Compose (fastest local evaluation)

Best if you want to try the UI + execute API in minutes on a laptop.

- Docs: [`deployments/docker/README.md`](docker/README.md)

### 2) Helm (recommended for Kubernetes)

Best for production-like installs and customization via `values.yaml`.

- Chart + docs: [`deployments/helm/agentfield`](helm/agentfield/README.md)
- Website guide: [agentfield.ai/guides/deployment/helm](https://agentfield.ai/guides/deployment/helm)

### 3) Kustomize (plain Kubernetes YAML)

Best if you want transparent manifests and minimal tooling.

- Docs: [`deployments/kubernetes/README.md`](kubernetes/README.md)
- Website guide: [agentfield.ai/guides/deployment/kubernetes](https://agentfield.ai/guides/deployment/kubernetes)

