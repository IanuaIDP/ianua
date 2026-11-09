'use client';

import dynamic from 'next/dynamic';

/** The editor, fetched only when a sandbox page draws it. */
export const CodeEditor = dynamic(
  () => import('@/components/dashboard/workflows/sandboxes/code-editor'),
  { loading: () => <div className="min-h-60 rounded-lg bg-appBg" />, ssr: false },
);
