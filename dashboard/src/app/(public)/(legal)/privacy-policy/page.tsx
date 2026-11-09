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
  PRIVACY_DATA_COLLECTED_IDS,
  PRIVACY_DATA_RECIPIENT_IDS,
} from '@/constants/legal';
import { DEFAULT_LOCALE } from '@/i18n/config';

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations('legal.privacy.meta');

  return { description: t('description'), title: t('title') };
}

export default async function PrivacyPolicyPage() {
  const tLegal = await getTranslations('legal');
  const t = await getTranslations('legal.privacy');
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
        <LegalSection title={t('demo.title')}>
          <LegalParagraph>{t('demo.body')}</LegalParagraph>
        </LegalSection>

        <LegalSection title={t('responsible.title')}>
          <LegalProse>
            <p>{t('responsible.p1')}</p>
            <p>{t.rich('responsible.p2', { ...legalRichTags, ...values })}</p>
            <p>{t('responsible.p3')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('collect.title')}>
          <LegalParagraph>{t('collect.intro')}</LegalParagraph>

          <div className="mt-4 overflow-hidden rounded-lg border border-borderGray">
            <table className="w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-borderGray bg-cardBg">
                  <th className="w-1/3 px-4 py-3 font-medium text-textGray sm:px-6">
                    {t('collect.tableWhat')}
                  </th>
                  <th className="px-4 py-3 font-medium text-textGray sm:px-6">
                    {t('collect.tableWhy')}
                  </th>
                </tr>
              </thead>
              <tbody>
                {PRIVACY_DATA_COLLECTED_IDS.map((id, index, ids) => (
                  <tr
                    key={id}
                    className={index < ids.length - 1 ? 'border-b border-borderGray' : ''}
                  >
                    <td className="px-4 py-3 align-top text-white sm:px-6">
                      {t(`collect.rows.${id}.what`)}
                    </td>
                    <td className="px-4 py-3 align-top text-textGray sm:px-6">
                      {t(`collect.rows.${id}.why`)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <LegalProse>
            <p>{t('collect.p1')}</p>
            <p>{t('collect.p2')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('recipients.title')}>
          <LegalParagraph>{t('recipients.intro')}</LegalParagraph>

          <LegalList>
            {PRIVACY_DATA_RECIPIENT_IDS.map((id) => (
              <LegalBullet key={id}>
                <span className="font-semibold text-white">
                  {t(`recipients.items.${id}.label`)}
                </span>{' '}
                &mdash; {t(`recipients.items.${id}.rest`)}
              </LegalBullet>
            ))}
          </LegalList>

          <LegalProse>
            <p>{t('recipients.p1')}</p>
            <p>{t('recipients.p2')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('retention.title')}>
          <LegalProse>
            <p>{t('retention.p1')}</p>
            <p>{t('retention.p2')}</p>
            <p>{t('retention.p3')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('rights.title')}>
          <LegalProse>
            <p>{t.rich('rights.p1', { ...legalRichTags, ...values })}</p>
            <p>{t('rights.p2')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('noRealData.title')}>
          <LegalProse>
            <p className="text-white">{t('noRealData.lead')}</p>
            <p>{t('noRealData.p1')}</p>
            <p>{t('noRealData.p2')}</p>
          </LegalProse>
        </LegalSection>

        <LegalSection title={t('children.title')}>
          <LegalParagraph>{t('children.body')}</LegalParagraph>
        </LegalSection>

        <LegalSection title={t('changes.title')}>
          <LegalParagraph>{t('changes.body')}</LegalParagraph>
        </LegalSection>

        <LegalSection title={t('security.title')}>
          <LegalParagraph>
            {t.rich('security.body', { ...legalRichTags, ...values })}
          </LegalParagraph>
        </LegalSection>
      </div>
    </div>
  );
}
