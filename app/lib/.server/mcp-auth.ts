import { createHash, timingSafeEqual } from 'node:crypto';
import { MCPService } from '~/lib/services/mcpService';

type MCPAuthContext = {
  cloudflare?: { env?: Pick<Env, 'MCP_OWNER_USERNAME' | 'MCP_OWNER_PASSWORD' | 'MCP_ALLOW_STDIO'> };
};

function ownerCredentials(context?: MCPAuthContext) {
  return {
    username: context?.cloudflare?.env?.MCP_OWNER_USERNAME ?? process.env.MCP_OWNER_USERNAME,
    password: context?.cloudflare?.env?.MCP_OWNER_PASSWORD ?? process.env.MCP_OWNER_PASSWORD,
  };
}

function isCrossSite(request: Request): boolean {
  const origin = request.headers.get('Origin');

  return (
    Boolean(origin && origin !== new URL(request.url).origin) || request.headers.get('Sec-Fetch-Site') === 'cross-site'
  );
}

export function getMCPPrincipal(request: Request, context?: MCPAuthContext): string | undefined {
  const { username, password } = ownerCredentials(context);

  if (typeof username !== 'string' || !username || typeof password !== 'string' || !password || isCrossSite(request)) {
    return undefined;
  }

  const authorization = request.headers.get('Authorization');
  const match = authorization?.match(/^Basic ([A-Za-z0-9+/]+={0,2})$/i);

  if (!match) {
    return undefined;
  }

  const expected = createHash('sha256').update(`${username}:${password}`).digest();
  const supplied = createHash('sha256').update(Buffer.from(match[1], 'base64')).digest();

  return timingSafeEqual(expected, supplied) ? Buffer.from(expected).toString('hex') : undefined;
}

export function requireMCPOwner(request: Request, context?: MCPAuthContext): string {
  const { username, password } = ownerCredentials(context);

  if (typeof username !== 'string' || !username || typeof password !== 'string' || !password) {
    throw new Response('MCP owner authentication is not configured', { status: 503 });
  }

  // Browser-cached Basic credentials must not authorize cross-site MCP requests.
  if (isCrossSite(request)) {
    throw new Response('Cross-site MCP requests are not allowed', { status: 403 });
  }

  const principal = getMCPPrincipal(request, context);

  if (!principal) {
    throw new Response('MCP owner authentication required', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="MCP owner", charset="UTF-8"' },
    });
  }

  return principal;
}

export function getMCPServiceForRequest(request: Request, context?: MCPAuthContext): MCPService {
  const principal = getMCPPrincipal(request, context);
  const allowStdio = (context?.cloudflare?.env?.MCP_ALLOW_STDIO ?? process.env.MCP_ALLOW_STDIO) === 'true';

  return principal ? MCPService.getInstance(principal, allowStdio) : new MCPService();
}
