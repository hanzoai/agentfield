import express from 'express';
import type http from 'node:http';
import { randomUUID } from 'node:crypto';
import type { AgentConfig, HealthStatus } from '../types/agent.js';
import { ReasonerRegistry } from './ReasonerRegistry.js';
import { SkillRegistry } from './SkillRegistry.js';
import { AgentRouter } from '../router/AgentRouter.js';
import type { ReasonerHandler, ReasonerOptions } from '../types/reasoner.js';
import type { SkillHandler, SkillOptions } from '../types/skill.js';
import { ExecutionContext, type ExecutionMetadata } from '../context/ExecutionContext.js';
import { ReasonerContext } from '../context/ReasonerContext.js';
import { SkillContext } from '../context/SkillContext.js';
import { AIClient } from '../ai/AIClient.js';
import { AgentFieldClient } from '../client/AgentFieldClient.js';
import { MemoryClient } from '../memory/MemoryClient.js';
import { MemoryEventClient } from '../memory/MemoryEventClient.js';
import {
  MemoryInterface,
  type MemoryChangeEvent,
  type MemoryWatchHandler
} from '../memory/MemoryInterface.js';
import { DidClient } from '../did/DidClient.js';
import { DidInterface } from '../did/DidInterface.js';
import { matchesPattern } from '../utils/pattern.js';
import { WorkflowReporter } from '../workflow/WorkflowReporter.js';
import type { DiscoveryOptions } from '../types/agent.js';
import type { MCPToolRegistration } from '../types/mcp.js';
import { MCPClientRegistry } from '../mcp/MCPClientRegistry.js';
import { MCPToolRegistrar } from '../mcp/MCPToolRegistrar.js';

export class Agent {
  readonly config: AgentConfig;
  readonly app: express.Express;
  readonly reasoners = new ReasonerRegistry();
  readonly skills = new SkillRegistry();
  private server?: http.Server;
  private heartbeatTimer?: NodeJS.Timeout;
  private readonly aiClient: AIClient;
  private readonly agentFieldClient: AgentFieldClient;
  private readonly memoryClient: MemoryClient;
  private readonly memoryEventClient: MemoryEventClient;
  private readonly didClient: DidClient;
  private readonly memoryWatchers: Array<{ pattern: string; handler: MemoryWatchHandler; scope?: string; scopeId?: string }> = [];
  private readonly mcpClientRegistry?: MCPClientRegistry;
  private readonly mcpToolRegistrar?: MCPToolRegistrar;

  constructor(config: AgentConfig) {
    const mcp = config.mcp
      ? {
          autoRegisterTools: config.mcp.autoRegisterTools ?? true,
          ...config.mcp
        }
      : undefined;

    this.config = {
      port: 8001,
      agentFieldUrl: 'http://localhost:8080',
      host: '0.0.0.0',
      didEnabled: config.didEnabled ?? true,
      ...config,
      mcp
    };

    this.app = express();
    this.app.use(express.json());

    this.aiClient = new AIClient(this.config.aiConfig);
    this.agentFieldClient = new AgentFieldClient(this.config);
    this.memoryClient = new MemoryClient(this.config.agentFieldUrl!, this.config.defaultHeaders);
    this.memoryEventClient = new MemoryEventClient(this.config.agentFieldUrl!, this.config.defaultHeaders);
    this.didClient = new DidClient(this.config.agentFieldUrl!, this.config.defaultHeaders);
    this.memoryEventClient.onEvent((event) => this.dispatchMemoryEvent(event));

    if (this.config.mcp?.servers?.length) {
      this.mcpClientRegistry = new MCPClientRegistry(this.config.devMode);
      this.mcpToolRegistrar = new MCPToolRegistrar(this, this.mcpClientRegistry, {
        namespace: this.config.mcp.namespace,
        tags: this.config.mcp.tags,
        devMode: this.config.devMode
      });
      this.mcpToolRegistrar.registerServers(this.config.mcp.servers);
    }

    this.registerDefaultRoutes();
  }

  reasoner<TInput = any, TOutput = any>(
    name: string,
    handler: ReasonerHandler<TInput, TOutput>,
    options?: ReasonerOptions
  ) {
    this.reasoners.register(name, handler, options);
    return this;
  }

  skill<TInput = any, TOutput = any>(
    name: string,
    handler: SkillHandler<TInput, TOutput>,
    options?: SkillOptions
  ) {
    this.skills.register(name, handler, options);
    return this;
  }

  includeRouter(router: AgentRouter) {
    this.reasoners.includeRouter(router);
    this.skills.includeRouter(router);
  }

  watchMemory(pattern: string | string[], handler: MemoryWatchHandler, options?: { scope?: string; scopeId?: string }) {
    const patterns = Array.isArray(pattern) ? pattern : [pattern];
    patterns.forEach((p) =>
      this.memoryWatchers.push({ pattern: p, handler, scope: options?.scope, scopeId: options?.scopeId })
    );
    this.memoryEventClient.start();
  }

  discover(options?: DiscoveryOptions) {
    return this.agentFieldClient.discoverCapabilities(options);
  }

  async registerMcpTools(): Promise<{ registered: MCPToolRegistration[] }> {
    if (!this.mcpToolRegistrar) return { registered: [] };
    return this.mcpToolRegistrar.registerAll();
  }

  getAIClient() {
    return this.aiClient;
  }

  getMemoryInterface(metadata?: ExecutionMetadata) {
    const defaultScope = this.config.memoryConfig?.defaultScope ?? 'workflow';
    const defaultScopeId =
      defaultScope === 'session'
        ? metadata?.sessionId
        : defaultScope === 'actor'
          ? metadata?.actorId
          : metadata?.workflowId ?? metadata?.runId ?? metadata?.sessionId ?? metadata?.actorId;
    return new MemoryInterface({
      client: this.memoryClient,
      eventClient: this.memoryEventClient,
      aiClient: this.aiClient,
      defaultScope,
      defaultScopeId,
      metadata: {
        workflowId: metadata?.workflowId ?? metadata?.runId,
        sessionId: metadata?.sessionId,
        actorId: metadata?.actorId,
        runId: metadata?.runId,
        executionId: metadata?.executionId,
        parentExecutionId: metadata?.parentExecutionId,
        callerDid: metadata?.callerDid,
        targetDid: metadata?.targetDid,
        agentNodeDid: metadata?.agentNodeDid,
        agentNodeId: this.config.nodeId
      }
    });
  }

  getWorkflowReporter(metadata: ExecutionMetadata) {
    return new WorkflowReporter(this.agentFieldClient, {
      executionId: metadata.executionId,
      runId: metadata.runId,
      workflowId: metadata.workflowId,
      agentNodeId: this.config.nodeId
    });
  }

  getDidInterface(metadata: ExecutionMetadata, defaultInput?: any) {
    return new DidInterface({
      client: this.didClient,
      metadata: {
        ...metadata,
        agentNodeDid: metadata.agentNodeDid ?? this.config.defaultHeaders?.['X-Agent-Node-DID']?.toString()
      },
      enabled: Boolean(this.config.didEnabled),
      defaultInput
    });
  }

  async serve(): Promise<void> {
    if (this.config.mcp?.autoRegisterTools !== false) {
      try {
        await this.registerMcpTools();
      } catch (err) {
        if (this.config.devMode) {
          console.warn('MCP tool registration failed', err);
        }
      }
    }

    await this.registerWithControlPlane();
    const port = this.config.port ?? 8001;
    const host = this.config.host ?? '0.0.0.0';
    // First heartbeat marks the node as starting; subsequent interval sets ready.
    await this.agentFieldClient.heartbeat('starting');
    await new Promise<void>((resolve, reject) => {
      this.server = this.app
        .listen(port, host, () => resolve())
        .on('error', reject);
    });
    this.memoryEventClient.start();
    this.startHeartbeat();
  }

  async shutdown(): Promise<void> {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }
    await new Promise<void>((resolve, reject) => {
      this.server?.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    this.memoryEventClient.stop();
  }

  async call(target: string, input: any) {
    const { agentId, name } = this.parseTarget(target);
    if (!agentId || agentId === this.config.nodeId) {
      const local = this.reasoners.get(name);
      if (!local) throw new Error(`Reasoner not found: ${name}`);
      const parentMetadata = ExecutionContext.getCurrent()?.metadata;
      const runId = parentMetadata?.runId ?? parentMetadata?.executionId ?? randomUUID();
      const metadata = {
        ...parentMetadata,
        executionId: randomUUID(),
        parentExecutionId: parentMetadata?.executionId,
        runId,
        workflowId: parentMetadata?.workflowId ?? runId
      };
      const dummyReq = {} as express.Request;
      const dummyRes = {} as express.Response;
      const execCtx = new ExecutionContext({
        input,
        metadata: {
          ...metadata,
          executionId: metadata.executionId ?? randomUUID()
        },
        req: dummyReq,
        res: dummyRes,
        agent: this
      });
      const startTime = Date.now();

      const emitEvent = async (status: 'running' | 'succeeded' | 'failed', payload: any) => {
        await this.agentFieldClient.publishWorkflowEvent({
          executionId: execCtx.metadata.executionId,
          runId: execCtx.metadata.runId ?? execCtx.metadata.executionId,
          workflowId: execCtx.metadata.workflowId,
          reasonerId: name,
          agentNodeId: this.config.nodeId,
          status,
          parentExecutionId: execCtx.metadata.parentExecutionId,
          parentWorkflowId: execCtx.metadata.workflowId,
          inputData: status === 'running' ? input : undefined,
          result: status === 'succeeded' ? payload : undefined,
          error: status === 'failed' ? (payload?.message ?? String(payload)) : undefined,
          durationMs: status === 'running' ? undefined : Date.now() - startTime
        });
      };

      await emitEvent('running', null);

      return ExecutionContext.run(execCtx, async () => {
        try {
          const result = await local.handler(
            new ReasonerContext({
              input,
              executionId: execCtx.metadata.executionId,
              runId: execCtx.metadata.runId,
              sessionId: execCtx.metadata.sessionId,
              actorId: execCtx.metadata.actorId,
              workflowId: execCtx.metadata.workflowId,
              parentExecutionId: execCtx.metadata.parentExecutionId,
              callerDid: execCtx.metadata.callerDid,
              targetDid: execCtx.metadata.targetDid,
              agentNodeDid: execCtx.metadata.agentNodeDid,
              req: dummyReq,
              res: dummyRes,
              agent: this,
              aiClient: this.aiClient,
              memory: this.getMemoryInterface(execCtx.metadata),
              workflow: this.getWorkflowReporter(execCtx.metadata),
              did: this.getDidInterface(execCtx.metadata, input)
            })
          );
          await emitEvent('succeeded', result);
          return result;
        } catch (err) {
          await emitEvent('failed', err);
          throw err;
        }
      });
    }

    const metadata = ExecutionContext.getCurrent()?.metadata;
    return this.agentFieldClient.execute(target, input, {
      runId: metadata?.runId ?? metadata?.executionId,
      workflowId: metadata?.workflowId ?? metadata?.runId,
      parentExecutionId: metadata?.executionId,
      sessionId: metadata?.sessionId,
      actorId: metadata?.actorId,
      callerDid: metadata?.callerDid,
      targetDid: metadata?.targetDid,
      agentNodeDid: metadata?.agentNodeDid,
      agentNodeId: this.config.nodeId
    });
  }

  private registerDefaultRoutes() {
    this.app.get('/health', (_req, res) => {
      res.json(this.health());
    });

    // MCP health probe expected by control-plane UI
    this.app.get('/health/mcp', async (_req, res) => {
      if (!this.mcpClientRegistry) {
        res.json({ status: 'disabled', totalServers: 0, healthyServers: 0, servers: [] });
        return;
      }

      try {
        const summary = await this.mcpClientRegistry.healthSummary();
        res.json(summary);
      } catch (err: any) {
        res.status(500).json({ status: 'error', error: err?.message ?? 'MCP health check failed' });
      }
    });

    this.app.get('/mcp/status', (_req, res) => {
      res.json(this.mcpStatus());
    });

    this.app.get('/status', (_req, res) => {
      res.json({
        ...this.health(),
        reasoners: this.reasoners.all().map((r) => r.name),
        skills: this.skills.all().map((s) => s.name)
      });
    });

    this.app.get('/reasoners', (_req, res) => {
      res.json(this.reasoners.all().map((r) => r.name));
    });

    this.app.get('/skills', (_req, res) => {
      res.json(this.skills.all().map((s) => s.name));
    });

    this.app.post('/api/v1/reasoners/*', (req, res) => this.executeReasoner(req, res, (req.params as any)[0]));
    this.app.post('/reasoners/:name', (req, res) => this.executeReasoner(req, res, req.params.name));

    this.app.post('/api/v1/skills/*', (req, res) => this.executeSkill(req, res, (req.params as any)[0]));
    this.app.post('/skills/:name', (req, res) => this.executeSkill(req, res, req.params.name));
  }

  private async executeReasoner(req: express.Request, res: express.Response, name: string) {
    const reasoner = this.reasoners.get(name);
    if (!reasoner) {
      res.status(404).json({ error: `Reasoner not found: ${name}` });
      return;
    }

    const metadata = this.buildMetadata(req);
    const execCtx = new ExecutionContext({ input: req.body, metadata, req, res, agent: this });

    return ExecutionContext.run(execCtx, async () => {
      try {
        const ctx = new ReasonerContext({
          input: req.body,
          executionId: metadata.executionId,
          runId: metadata.runId,
          sessionId: metadata.sessionId,
          actorId: metadata.actorId,
          workflowId: metadata.workflowId,
          parentExecutionId: metadata.parentExecutionId,
          callerDid: metadata.callerDid,
          targetDid: metadata.targetDid,
          agentNodeDid: metadata.agentNodeDid,
          req,
          res,
          agent: this,
          aiClient: this.aiClient,
          memory: this.getMemoryInterface(metadata),
          workflow: this.getWorkflowReporter(metadata),
          did: this.getDidInterface(metadata, req.body)
        });

        const result = await reasoner.handler(ctx);
        res.json(result);
      } catch (err: any) {
        res.status(500).json({ error: err?.message ?? 'Execution failed' });
      }
    });
  }

  private async executeSkill(req: express.Request, res: express.Response, name: string) {
    const skill = this.skills.get(name);
    if (!skill) {
      res.status(404).json({ error: `Skill not found: ${name}` });
      return;
    }

    const metadata = this.buildMetadata(req);
    const execCtx = new ExecutionContext({ input: req.body, metadata, req, res, agent: this });

    return ExecutionContext.run(execCtx, async () => {
      try {
        const ctx = new SkillContext({
          input: req.body,
          executionId: metadata.executionId,
          sessionId: metadata.sessionId,
          workflowId: metadata.workflowId,
          req,
          res,
          agent: this,
          memory: this.getMemoryInterface(metadata),
          workflow: this.getWorkflowReporter(metadata),
          did: this.getDidInterface(metadata, req.body)
        });

        const result = await skill.handler(ctx);
        res.json(result);
      } catch (err: any) {
        res.status(500).json({ error: err?.message ?? 'Execution failed' });
      }
    });
  }

  private buildMetadata(req: express.Request) {
    const executionIdHeader = req.headers['x-execution-id'] as string | undefined;
    const runIdHeader = req.headers['x-run-id'] as string | undefined;
    const executionId = executionIdHeader ?? randomUUID();
    const runId = runIdHeader ?? executionId;
    const workflowIdHeader = (req.headers['x-workflow-id'] as string | undefined) ?? runId;
    return {
      executionId,
      runId,
      sessionId: req.headers['x-session-id'] as string | undefined,
      actorId: req.headers['x-actor-id'] as string | undefined,
      workflowId: workflowIdHeader,
      parentExecutionId: req.headers['x-parent-execution-id'] as string | undefined,
      callerDid: req.headers['x-caller-did'] as string | undefined,
      targetDid: req.headers['x-target-did'] as string | undefined,
      agentNodeDid:
        (req.headers['x-agent-node-did'] as string | undefined) ??
        (req.headers['x-agent-did'] as string | undefined)
    };
  }

  private async registerWithControlPlane() {
    try {
      const reasoners = this.reasoners.all().map((r) => ({
        id: r.name,
        input_schema: r.options?.inputSchema ?? {},
        output_schema: r.options?.outputSchema ?? {},
        memory_config: r.options?.memoryConfig ?? {
          auto_inject: [] as string[],
          memory_retention: '',
          cache_results: false
        },
        tags: r.options?.tags ?? []
      }));

      const skills = this.skills.all().map((s) => ({
        id: s.name,
        input_schema: s.options?.inputSchema ?? {},
        tags: s.options?.tags ?? []
      }));

      const port = this.config.port ?? 8001;
      const hostForUrl = this.config.publicUrl
        ? undefined
        : (this.config.host && this.config.host !== '0.0.0.0' ? this.config.host : '127.0.0.1');
      const publicUrl =
        this.config.publicUrl ?? `http://${hostForUrl ?? '127.0.0.1'}:${port}`;

      await this.agentFieldClient.register({
        id: this.config.nodeId,
        version: this.config.version,
        base_url: publicUrl,
        public_url: publicUrl,
        deployment_type: 'long_running',
        reasoners,
        skills
      });
    } catch (err) {
      if (!this.config.devMode) {
        throw err;
      }
      console.warn('Control plane registration failed (devMode=true), continuing locally', err);
    }
  }

  private startHeartbeat() {
    const interval = this.config.heartbeatIntervalMs ?? 30_000;
    if (interval <= 0) return;

    const tick = async () => {
      try {
        await this.agentFieldClient.heartbeat('ready');
      } catch (err) {
        if (!this.config.devMode) {
          console.warn('Heartbeat failed', err);
        }
      }
    };

    this.heartbeatTimer = setInterval(tick, interval);
    tick();
  }

  private health(): HealthStatus {
    return {
      status: 'running',
      nodeId: this.config.nodeId,
      version: this.config.version
    };
  }

  private mcpStatus() {
    const servers = this.mcpClientRegistry
      ? this.mcpClientRegistry.list().map((client) => ({
          alias: client.alias,
          baseUrl: client.baseUrl,
          transport: client.transport
        }))
      : [];

    const skills = this.skills
      .all()
      .filter((skill) => skill.options?.tags?.includes('mcp'))
      .map((skill) => skill.name);

    return {
      status: servers.length ? 'configured' : 'disabled',
      servers,
      skills
    };
  }

  private dispatchMemoryEvent(event: MemoryChangeEvent) {
    this.memoryWatchers.forEach(({ pattern, handler, scope, scopeId }) => {
      const scopeMatch = (!scope || scope === event.scope) && (!scopeId || scopeId === event.scopeId);
      if (scopeMatch && matchesPattern(pattern, event.key)) {
        handler(event);
      }
    });
  }

  private parseTarget(target: string): { agentId?: string; name: string } {
    if (!target.includes('.')) {
      return { name: target };
    }
    const [agentId, remainder] = target.split('.', 2);
    const name = remainder.replace(':', '/');
    return { agentId, name };
  }
}
