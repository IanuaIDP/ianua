import type { NextConfig } from 'next';
import createNextIntlPlugin from 'next-intl/plugin';

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts');

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle for a minimal production image.
  output: 'standalone',
  // The blog reads its MDX files at run time, so the standalone bundle must carry them.
  outputFileTracingIncludes: {
    '/blog': ['./content/blog/**/*'],
    '/blog/[slug]': ['./content/blog/**/*'],
  },
};

export default withNextIntl(nextConfig);
