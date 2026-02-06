/**
 * Permission Agent B (Protected Target) — TypeScript SDK
 *
 * A protected agent with tags ["sensitive", "analytics"]. The "sensitive"
 * tag matches the existing protection rule in agentfield.yaml:
 *
 *   pattern_type: "tag"
 *   pattern: "sensitive"
 *   description: "Agents tagged sensitive require permission"
 *
 * This tests TAG-BASED protection (different from the Go SDK tests which
 * use agent_id pattern matching), and also generates Verifiable Credentials
 * on successful executions to test the VC + authorization integration.
 *
 * Reasoners:
 *   - analyze_data  — simulates data analysis, generates a VC on success
 *   - generate_report — simulates report generation, generates a VC on success
 */

import { Agent } from '@agentfield/sdk';

async function main() {
  const agent = new Agent({
    nodeId: 'ts-perm-target',
    agentFieldUrl: process.env.AGENTFIELD_URL ?? 'http://localhost:8080',
    port: Number(process.env.PORT ?? 8006),
    version: '1.0.0',
    devMode: true,
    didEnabled: true,
  });

  // Reasoner 1: analyze_data — simulates data analysis with VC generation.
  agent.reasoner('analyze_data', async (ctx) => {
    const startTime = Date.now();
    const query = ctx.input.query ?? 'no query provided';

    const result = {
      status: 'analyzed',
      agent: 'ts-perm-target',
      query,
      insights: [
        { metric: 'total_records', value: 1542 },
        { metric: 'avg_processing_time_ms', value: 23.7 },
        { metric: 'error_rate', value: 0.003 },
      ],
      message: `Analysis complete for query: ${query}`,
      vcGenerated: false as boolean,
      vcId: undefined as string | undefined,
    };

    // Generate a Verifiable Credential for this execution
    try {
      const credential = await ctx.did.generateCredential({
        inputData: ctx.input,
        outputData: { insights: result.insights },
        status: 'succeeded',
        durationMs: Date.now() - startTime,
      });

      result.vcGenerated = true;
      result.vcId = credential.vcId;
      console.log(`[VC] Generated credential for analyze_data: ${credential.vcId}`);
    } catch (error) {
      console.error('[VC] Failed to generate credential:', error);
    }

    return result;
  }, {
    description: 'Analyze data. Protected operation with VC generation.',
    tags: ['sensitive', 'analytics'],
  });

  // Reasoner 2: generate_report — simulates report generation with VC.
  agent.reasoner('generate_report', async (ctx) => {
    const startTime = Date.now();
    const reportType = ctx.input.type ?? 'summary';

    const result = {
      status: 'generated',
      agent: 'ts-perm-target',
      reportType,
      report: {
        title: `${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Report`,
        generatedAt: new Date().toISOString(),
        sections: ['overview', 'metrics', 'recommendations'],
        pageCount: 12,
      },
      message: `Report generated: ${reportType}`,
      vcGenerated: false as boolean,
      vcId: undefined as string | undefined,
    };

    // Generate a Verifiable Credential for this execution
    try {
      const credential = await ctx.did.generateCredential({
        inputData: ctx.input,
        outputData: { reportType: result.reportType, pageCount: result.report.pageCount },
        status: 'succeeded',
        durationMs: Date.now() - startTime,
      });

      result.vcGenerated = true;
      result.vcId = credential.vcId;
      console.log(`[VC] Generated credential for generate_report: ${credential.vcId}`);
    } catch (error) {
      console.error('[VC] Failed to generate credential:', error);
    }

    return result;
  }, {
    description: 'Generate a report. Protected operation with VC generation.',
    tags: ['sensitive', 'analytics', 'reporting'],
  });

  await agent.serve();

  console.log(`
Permission Agent B (Protected) — TypeScript SDK
Node: ts-perm-target
Port: ${agent.config.port}
Server: ${agent.config.agentFieldUrl}
Tags: sensitive, analytics
Reasoners: analyze_data, generate_report
  `);
}

main().catch((err) => {
  console.error('Failed to start agent:', err);
  process.exit(1);
});
