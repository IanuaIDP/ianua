import type { NextConfig } from 'next';
import createNextIntlPlugin from 'next-intl/plugin';

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts');

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle for a minimal production image.
  output: 'standalone',
};

export default withNextIntl(nextConfig);
