import type { ActionFunctionArgs } from 'react-router';
import { getMCPServiceForRequest, requireMCPOwner } from '~/lib/.server/mcp-auth';
import { withSecurity } from '~/lib/security';
import { mcpConfigSchema } from '~/lib/services/mcpService';
import { createScopedLogger } from '~/utils/logger';

const logger = createScopedLogger('api.mcp-update-config');

export const action = withSecurity(
  async ({ request, context }: ActionFunctionArgs) => {
    requireMCPOwner(request, context);

    if (request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') {
      return Response.json({ error: 'Expected application/json' }, { status: 415 });
    }

    try {
      const result = mcpConfigSchema.safeParse(await request.json().catch(() => undefined));

      if (!result.success) {
        return Response.json({ error: 'Invalid MCP servers configuration' }, { status: 400 });
      }

      const mcpService = getMCPServiceForRequest(request, context);
      const serverTools = await mcpService.updateConfig(result.data);

      return Response.json(serverTools, { headers: { 'Cache-Control': 'no-store' } });
    } catch (error) {
      logger.error('Error updating MCP config:', error);
      return Response.json({ error: 'Failed to update MCP config' }, { status: 500 });
    }
  },
  { allowedMethods: ['POST'] },
);
