'use client';

import { useEffect, useRef } from 'react';

type BrowserFormPostProps = {
  action: string;
  fields: Record<string, string>;
};

/** Posts the fields to `action` as soon as it renders, as SAML and OAuth answers ask. */
export function BrowserFormPost({ action, fields }: BrowserFormPostProps) {
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    formRef.current?.submit();
  }, []);

  return (
    <form ref={formRef} action={action} method="post" aria-hidden="true" className="hidden">
      {Object.entries(fields).map(([name, value]) => (
        <input key={name} type="hidden" name={name} value={value} />
      ))}
    </form>
  );
}
