import { ReactNode } from 'react';
import type { Metadata } from 'next';
import { NextIntlClientProvider } from 'next-intl';
import { getLocale } from 'next-intl/server';

import { AppProviders } from '@/lib/providers/app-providers';
import { materialSymbolsRounded } from '@/lib/fonts';

import './globals.css';

export const metadata: Metadata = {
  title: 'IANUA',
  description: 'Next.js application.',
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: ReactNode;
}>) {
  const locale = await getLocale();

  return (
    <html lang={locale} className={`scroll-smooth ${materialSymbolsRounded.variable}`}>
      <body>
        <NextIntlClientProvider>
          <AppProviders>{children}</AppProviders>
        </NextIntlClientProvider>
      </body>
    </html>
  );
}
