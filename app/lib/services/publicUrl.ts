function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');

  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    return true;
  }

  // URL normalizes alternate IPv4 spellings (integer, octal, hex) to dotted decimal.
  if (/^\d+(?:\.\d+){0,3}$/.test(host)) {
    const parts = host.split('.').map(Number);

    if (parts.length !== 4 || parts.some((part) => part < 0 || part > 255)) {
      return true;
    }

    const [a, b] = parts;

    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a === 224 ||
      a >= 240
    );
  }

  /*
   * Reject IP-literal IPv6 entirely: global IPv6 is uncommon for fetched pages and
   * conservative rejection avoids loopback, ULA, link-local and mapped-address tricks.
   */
  return host.includes(':') || host.startsWith('[');
}

export function validatePublicHttpUrl(input: string): URL {
  let url: URL;

  try {
    url = new URL(input);
  } catch {
    throw new Error('A valid HTTP or HTTPS URL is required');
  }

  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password) {
    throw new Error('Only public HTTP/HTTPS URLs without embedded credentials are allowed');
  }

  if (isBlockedHostname(url.hostname)) {
    throw new Error('Private, local, and reserved network addresses are not allowed');
  }

  return url;
}
