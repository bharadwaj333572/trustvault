import fs from 'fs';
import path from 'path';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export interface DiscoveredRoute {
  /** Absolute filesystem path to route.ts */
  filePath: string;
  /** Path relative to src/app (posix style) */
  relativeFile: string;
  /** URL path template, e.g. /api/documents/:id/download */
  pathTemplate: string;
  methods: HttpMethod[];
}

const METHOD_RE = /export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;

/**
 * Convert an App Router file path into a URL path template.
 * e.g. api/documents/[id]/download/route.ts -> /api/documents/:id/download
 */
export function filePathToPathTemplate(relativeToApp: string): string {
  const withoutRoute = relativeToApp.replace(/\\/g, '/').replace(/\/route\.ts$/, '');
  const segments = withoutRoute.split('/').map((seg) => {
    const m = seg.match(/^\[(\.\.\.)?(.+)\]$/);
    if (m) return `:${m[2]}`;
    return seg;
  });
  return '/' + segments.join('/');
}

/**
 * Recursively find every App Router route.ts under src/app and parse exported HTTP methods.
 */
export function discoverAppRoutes(appDir?: string): DiscoveredRoute[] {
  const root = appDir || path.resolve(process.cwd(), 'src', 'app');
  const results: DiscoveredRoute[] = [];

  function walk(dir: string) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (entry.name !== 'route.ts') continue;

      const relativeFile = path.relative(root, full).replace(/\\/g, '/');
      const source = fs.readFileSync(full, 'utf8');
      const methods = new Set<HttpMethod>();
      let match: RegExpExecArray | null;
      METHOD_RE.lastIndex = 0;
      while ((match = METHOD_RE.exec(source)) !== null) {
        methods.add(match[1] as HttpMethod);
      }

      results.push({
        filePath: full,
        relativeFile,
        pathTemplate: filePathToPathTemplate(relativeFile),
        methods: Array.from(methods).sort() as HttpMethod[],
      });
    }
  }

  walk(root);
  return results.sort((a, b) => a.pathTemplate.localeCompare(b.pathTemplate) || a.relativeFile.localeCompare(b.relativeFile));
}

/**
 * Flatten discovered routes into method+path keys: "GET /api/documents/:id"
 */
export function flattenRouteKeys(routes: DiscoveredRoute[]): string[] {
  const keys: string[] = [];
  for (const route of routes) {
    for (const method of route.methods) {
      keys.push(`${method} ${route.pathTemplate}`);
    }
  }
  return keys.sort();
}

/**
 * Discover `"use server"` modules and exported async function names (server actions).
 */
export function discoverServerActions(srcDir?: string): Array<{ file: string; actions: string[] }> {
  const root = srcDir || path.resolve(process.cwd(), 'src');
  const found: Array<{ file: string; actions: string[] }> = [];

  function walk(dir: string) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.next') continue;
        walk(full);
        continue;
      }
      if (!/\.(ts|tsx)$/.test(entry.name)) continue;
      const source = fs.readFileSync(full, 'utf8');
      // Match the Next.js directive only (line-start / after optional comments), not docstrings.
      if (!/(^|\n)\s*['"]use server['"]\s*;?/.test(source)) continue;
      const actions: string[] = [];
      const exportRe = /export\s+async\s+function\s+([A-Za-z0-9_]+)/g;
      let m: RegExpExecArray | null;
      while ((m = exportRe.exec(source)) !== null) {
        actions.push(m[1]);
      }
      found.push({
        file: path.relative(process.cwd(), full).replace(/\\/g, '/'),
        actions,
      });
    }
  }

  walk(root);
  return found;
}
