import type { LoaderFunctionArgs } from 'react-router';
import { getMCPServiceForRequest, requireMCPOwner } from '~/lib/.server/mcp-auth';
import { withSecurity } from '~/lib/security';
import { createScopedLogger } from '~/utils/logger';

const logger = createScopedLogger('api.mcp-check');

export const loader = withSecurity(
  async ({ request, context }: LoaderFunctionArgs) => {
    requireMCPOwner(request, context);

    try {
      const mcpService = getMCPServiceForRequest(request, context);
      const serverTools = await mcpService.checkServersAvailabilities();

      return Response.json(serverTools, { headers: { 'Cache-Control': 'no-store' } });
    } catch (error) {
      logger.error('Error checking MCP servers:', error);
      return Response.json({ error: 'Failed to check MCP servers' }, { status: 500 });
    }
  },
  { allowedMethods: ['GET'] },
);
