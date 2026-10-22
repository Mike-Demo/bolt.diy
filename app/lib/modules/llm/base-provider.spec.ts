import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BaseProvider } from './base-provider';
import { setEnv } from './env';

class FakeProvider extends BaseProvider {
  name = 'FakeProvider';
  staticModels = [];
  config = { baseUrlKey: 'FAKE_BASE_URL', apiTokenKey: 'FAKE_API_KEY' };

  getModelInstance(): any {
    throw new Error('not implemented');
  }
}

describe('BaseProvider.getProviderBaseUrlAndKey', () => {
  beforeEach(() => setEnv({}));
  afterEach(() => setEnv({}));

  it('uses only the caller key with a caller-supplied base URL', () => {
    const provider = new FakeProvider();

    const resolved = provider.getProviderBaseUrlAndKey({
      providerSettings: { baseUrl: 'https://models.example.com/v1/' },
      serverEnv: { FAKE_API_KEY: 'server-secret', FAKE_BASE_URL: 'https://operator.example.com' },
      defaultBaseUrlKey: 'FAKE_BASE_URL',
      defaultApiTokenKey: 'FAKE_API_KEY',
    });

    expect(resolved).toEqual({ baseUrl: 'https://models.example.com/v1', apiKey: undefined });
  });

  it('uses a caller key with the caller-supplied base URL', () => {
    const provider = new FakeProvider();

    const resolved = provider.getProviderBaseUrlAndKey({
      apiKeys: { FakeProvider: 'caller-key' },
      providerSettings: { baseUrl: 'https://models.example.com/v1' },
      serverEnv: { FAKE_API_KEY: 'server-secret' },
      defaultBaseUrlKey: 'FAKE_BASE_URL',
      defaultApiTokenKey: 'FAKE_API_KEY',
    });

    expect(resolved.apiKey).toBe('caller-key');
  });

  it('rejects a caller-supplied private base URL', () => {
    const provider = new FakeProvider();

    expect(() =>
      provider.getProviderBaseUrlAndKey({
        providerSettings: { baseUrl: 'http://127.0.0.1:8080' },
        serverEnv: { FAKE_API_KEY: 'server-secret' },
        defaultBaseUrlKey: 'FAKE_BASE_URL',
        defaultApiTokenKey: 'FAKE_API_KEY',
      }),
    ).toThrow('Private, local, and reserved network addresses are not allowed');
  });

  it('keeps environment credentials bound to the operator base URL', () => {
    const provider = new FakeProvider();

    const resolved = provider.getProviderBaseUrlAndKey({
      serverEnv: { FAKE_API_KEY: 'server-secret', FAKE_BASE_URL: 'https://operator.example.com/' },
      defaultBaseUrlKey: 'FAKE_BASE_URL',
      defaultApiTokenKey: 'FAKE_API_KEY',
    });

    expect(resolved).toEqual({ baseUrl: 'https://operator.example.com', apiKey: 'server-secret' });
  });
});
