# Security audit remediation backlog

Prepared from [parent issue #1](https://github.com/Mike-Demo/bolt.diy/issues/1). The audit reports four confirmed findings and no needs-validation leads. The drafts below are ordered by real-world risk and then by the size and safety of the proposed remediation.

The high provider-base-URL finding and the medium anonymous LLM-use finding both involve `BaseProvider.getProviderBaseUrlAndKey` falling back to server environment credentials. They remain separate issues because one enables sending credentials to a caller-chosen host, while the other enables anonymous use of the deployment's provider accounts; their required controls differ.

## 1. Critical — unauthenticated command execution and shared MCP poisoning

**Issue title**

`[security][critical] Prevent unauthenticated MCP config command execution`

**Issue body**

### Finding

Unauthenticated `POST /api/mcp-update-config` passes the raw request body to the process-global `MCPService` singleton. The service immediately creates MCP clients; for stdio entries it constructs `Experimental_StdioMCPTransport` using caller-supplied `command`, `args`, `cwd`, and `env` without an allowlist. Calling `client.tools()` starts the transport and spawns the command in the server process. Registered tools are stored on the shared singleton, affecting all users.

**Fingerprint:** `mcp-update-config-unauthenticated-stdio-spawn-and-global-tool-poisoning`

### Root cause

The route has no authentication, security wrapper, or rate limiting, and the shared `MCPService` trusts caller-supplied stdio configuration and exposes its resulting tool set across principals.

### Smallest fix

Require owner authentication on `/api/mcp-update-config` and `/api/mcp-check`; scope MCP service state per authenticated principal; and reject stdio transports on server runtimes unless an explicit operator environment flag enables them.

Parent: #1

## 2. High — prevent provider credentials from going to caller-chosen hosts

**Issue title**

`[security][high] Bind provider API keys to validated base URLs`

**Issue body**

### Finding

The unauthenticated `/api/models` route accepts provider settings from the caller's `providers` cookie. The cookie's `baseUrl` is not validated. The LLM manager prefers that caller-controlled URL while independently falling back to the deployment owner's server-environment API key. Providers such as `OpenAILike` then make server-side requests to `<baseUrl>/models` with the API key in the Authorization header.

**Fingerprint:** `provider-baseurl-override-sends-server-env-key-to-caller-chosen-host`

### Root cause

`BaseProvider.getProviderBaseUrlAndKey` selects the URL from caller settings without validation, while independently allowing the API key to fall back to `serverEnv`, `process.env`, or `managerEnv`. The provider path does not apply the existing `validatePublicHttpUrl` helper.

### Smallest fix

Bind credential source to destination: if the base URL comes from caller settings, use only a caller-supplied key; if an environment key is used, pin the URL to the provider default or operator-configured value. Also validate caller-supplied base URLs with the existing `validatePublicHttpUrl` helper.

Parent: #1

## 3. Medium — restrict the unauthenticated Git proxy

**Issue title**

`[security][medium] Restrict git proxy hosts and forwarded authorization`

**Issue body**

### Finding

The unauthenticated `/api/git-proxy/*` route accepts any caller-supplied domain, constructs an HTTPS upstream URL without a host allowlist or private-address check, and forwards headers including `authorization` verbatim. It follows redirects, streams request bodies, and returns responses with `Access-Control-Allow-Origin: *`. Anonymous callers can use a deployed instance as an open HTTPS proxy and forward credentials to non-provider hosts.

**Fingerprint:** `git-proxy-unauthenticated-open-proxy-arbitrary-https-host`

### Root cause

`handleProxyRequest` in `app/routes/api.git-proxy.$.ts` builds the upstream URL directly from caller-controlled path input and forwards authorization without host validation, authentication, or rate limiting.

### Smallest fix

Allow only approved Git provider hosts (`github.com`, `api.github.com`, `gitlab.com`, and operator-configured self-hosted hosts); forward `Authorization` only to those hosts; and require the same instance access control as other server routes when the instance is shared.

Parent: #1

## 4. Medium — prevent anonymous use of deployment LLM credentials

**Issue title**

`[security][medium] Require access control for server-funded LLM routes`

**Issue body**

### Finding

Anonymous callers can make billed LLM calls using deployment-owned environment API keys through `/api/chat`, `/api/llmcall`, and `/api/enhancer`. `BaseProvider.getProviderBaseUrlAndKey` falls back from a caller cookie key to server environment credentials. The routes do not enforce authentication: although `withSecurity` declares a `requireAuth` option, its wrapper does not check it and no route passes it.

**Fingerprint:** `unauthenticated-use-of-server-env-llm-keys`

### Root cause

Environment-key fallback is combined with the absence of authentication enforcement on the LLM routes, allowing anonymous requests to inherit the deployment's credentials.

### Smallest fix

Add instance access control (an operator-set access password or token checked by `withSecurity`'s `requireAuth`) for the LLM routes, or make environment-key fallback opt-in through an explicit operator flag that defaults off and otherwise return the existing missing-credential error.

Parent: #1

## Needs-validation checklist issue

**Issue title**

`[security][needs-validation] Audit leads to validate`

**Issue body**

The parent audit reports **zero needs-validation leads**. There are no checklist items or missing facts to validate.

Parent: #1
