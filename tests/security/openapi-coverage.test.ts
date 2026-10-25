import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { discoverAppRoutes } from '@/server/security/discover-routes';

describe('OpenAPI Specification Route Coverage & Conformance', () => {
  const openApiPath = path.resolve(process.cwd(), 'docs/openapi.yaml');

  it('fails if docs/openapi.yaml is missing', () => {
    expect(fs.existsSync(openApiPath)).toBe(true);
  });

  it('verifies that every API route in the application is documented in OpenAPI spec', () => {
    const yamlContent = fs.readFileSync(openApiPath, 'utf-8');
    const appRoutes = discoverAppRoutes().filter((r) => r.pathTemplate.startsWith('/api/'));

    const documentedPaths: string[] = [];
    const pathRegex = /^\s{2}(\/api\/[^\s:]+):/gm;
    let match;
    while ((match = pathRegex.exec(yamlContent)) !== null) {
      documentedPaths.push(match[1]);
    }

    const missingRoutes: string[] = [];

    for (const route of appRoutes) {
      // Normalize dynamic route param :param to {param}
      const normalizedRoute = route.pathTemplate.replace(/:([a-zA-Z0-9_]+)/g, '{$1}');

      const isDocumented = documentedPaths.some((p) => p === normalizedRoute);
      if (!isDocumented) {
        missingRoutes.push(route.pathTemplate);
      }
    }

    expect(missingRoutes, `Unregistered API routes missing from docs/openapi.yaml: ${missingRoutes.join(', ')}`).toEqual([]);
  });
});
