import type { Metadata } from 'next';
import { getLocale, getTranslations } from 'next-intl/server';

import {
  LegalBullet,
  LegalList,
  LegalParagraph,
  LegalProse,
  LegalSection,
  legalRichTags,
} from '@/components/legal/legal-prose';
import {
  LEGAL_CONTACT_EMAIL,
  LEGAL_LAST_UPDATED,
  TERMS_PROHIBITED_USE_IDS,
} from '@/constants/legal';
import { DEFAULT_LOCALE } from '@/i18n/config';

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations('legal.terms.meta');

  return { description: t('description'), title: t('title') };
}

export default async function TermsOfUsePage() {
  const tLegal = await getTranslations('legal');
  const t = await getTranslations('legal.terms');
  const locale = await getLocale();
  const values = { email: LEGAL_CONTACT_EMAIL };

  return (
    <div className="mx-auto max-w-3xl px-6 py-16 sm:py-20">
      <h1 className="font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-tight text-white sm:text-4xl">
        {t.rich('heading', legalRichTags)}
      </h1>
      <p className="mt-4 text-sm text-textGray">
        {tLegal('lastUpdated', { date: LEGAL_LAST_UPDATED })}
      </p>
      {locale !== DEFAULT_LOCALE ? (
        <p className="mt-4 rounded-lg border border-borderGray bg-cardBg px-4 py-3 text-sm text-textGray">
          {tLegal('translationNotice')}
        </p>
      ) : null}

      <div className="mt-12 space-y-12">
        <LegalSection title={t('what.title')}>
          <LegalProse>
            <p>{t('what.p1')}</p>
            <p>{t('what.p2')}</p>
            <p>{t.rich('what.p3', { ...legalRichTags, ...values })}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('expect.title')}>
          <LegalProse>
            <p>{t('expect.p1')}</p>
            <p>{t('expect.p2')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('ofYou.title')}>
          <LegalParagraph>{t('ofYou.intro')}</LegalParagraph>

          <LegalList>
            {TERMS_PROHIBITED_USE_IDS.map((id) => (
              <LegalBullet key={id}>{t(`ofYou.items.${id}`)}</LegalBullet>
            ))}
          </LegalList>

          <LegalParagraph>{t('ofYou.outro')}</LegalParagraph>
        </LegalSection>

        <LegalSection title={t('production.title')}>
          <LegalProse>
            <p>{t('production.p1')}</p>
            <p>{t('production.p2')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('research.title')}>
          <LegalParagraph>
            {t.rich('research.body', { ...legalRichTags, ...values })}
          </LegalParagraph>
        </LegalSection>

        <LegalSection title={t('data.title')}>
          <LegalProse>
            <p>{t.rich('data.p1', legalRichTags)}</p>
            <p>{t('data.p2')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t.rich('software.title', legalRichTags)}>
          <LegalParagraph>{t('software.body')}</LegalParagraph>
        </LegalSection>

        <LegalSection title={t('liability.title')}>
          <LegalProse>
            <p>{t('liability.p1')}</p>
            <p>{t('liability.p2')}</p>
            <p>{t('liability.p3')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('ending.title')}>
          <LegalParagraph>{t('ending.body')}</LegalParagraph>
        </LegalSection>

        <LegalSection title={t('company.title')}>
          <LegalParagraph>{t('company.body')}</LegalParagraph>
        </LegalSection>

        <LegalSection title={t('law.title')}>
          <LegalProse>
            <p>{t('law.p1')}</p>
            <p>{t('law.p2')}</p>
          </LegalProse>
        </LegalSection>
      </div>
    </div>
  );
}
