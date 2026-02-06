/**
 * Permission Agent A (Caller) — TypeScript SDK
 *
 * A normal agent that tries to call ts-perm-target (a protected agent).
 * Used to test the VC authorization system with the TypeScript SDK.
 *
 * Test flow:
 *  1. Start control plane with authorization enabled
 *  2. Start ts-perm-target (permission-agent-b)
 *  3. Start ts-perm-caller (this agent)
 *  4. POST /api/v1/execute/ts-perm-caller.call_analytics
 *     -> Calls ts-perm-target.analyze_data via the control plane
 *     -> Should be denied (403) until an admin approves the permission
 *
 * The ts-perm-target agent is protected by the tag-based rule:
 *   pattern_type: "tag", pattern: "sensitive"
 */

import { Agent } from '@agentfield/sdk';

async function main() {
  const agent = new Agent({
    nodeId: 'ts-perm-caller',
    agentFieldUrl: process.env.AGENTFIELD_URL ?? 'http://localhost:8080',
    port: Number(process.env.PORT ?? 8005),
    version: '1.0.0',
    devMode: true,
    didEnabled: true,
  });

  // Simple health check — no cross-agent call, should always work.
  agent.reasoner('ping', async (ctx) => {
    return {
      status: 'ok',
      agent: 'ts-perm-caller',
    };
  }, {
    description: 'Simple health check',
  });

  // Calls ts-perm-target.analyze_data through the control plane.
  // This triggers the permission check middleware since ts-perm-target
  // is a protected agent (matched by tag pattern "sensitive").
  agent.reasoner('call_analytics', async (ctx) => {
    const query = ctx.input.query ?? 'default analytics query';

    const result = await agent.call('ts-perm-target.analyze_data', {
      query,
    });

    return {
      source: 'ts-perm-caller',
      delegation_result: result,
    };
  }, {
    description: 'Calls ts-perm-target.analyze_data through the control plane',
  });

  await agent.serve();

  console.log(`
Permission Agent A (Caller) — TypeScript SDK
Node: ts-perm-caller
Port: ${agent.config.port}
Server: ${agent.config.agentFieldUrl}
  `);
}

main().catch((err) => {
  console.error('Failed to start agent:', err);
  process.exit(1);
});
