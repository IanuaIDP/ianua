import { NextResponse } from 'next/server';

import { ORG_SSO_SAML_ANSWER_STORAGE_KEY } from '@/lib/auth/org-sso';

/**
 * Where an identity provider posts a SAML answer. The answer is too big for
 * an address and a cookie, so this hands it to the tab through session
 * storage and goes on to the page that finishes the sign-in.
 */
export async function POST(request: Request) {
  const form = await request.formData();
  const answer = {
    protocol: 'saml',
    relay_state: String(form.get('RelayState') ?? ''),
    saml_response: String(form.get('SAMLResponse') ?? ''),
  };
  const script = [
    `sessionStorage.setItem(${JSON.stringify(ORG_SSO_SAML_ANSWER_STORAGE_KEY)}, ${escapeForScript(JSON.stringify(JSON.stringify(answer)))});`,
    `location.replace('/login/sso/saml/complete');`,
  ].join('');

  return new NextResponse(`<!doctype html><script>${script}</script>`, {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/html; charset=utf-8',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

function escapeForScript(value: string) {
  return value.replace(/</g, '\\u003c');
}
