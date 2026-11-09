'use client';

import Image from 'next/image';
import Link from 'next/link';
import { useTranslations } from 'next-intl';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMemo, useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';

import contactBackground from '@/assets/contact-background.svg';
import { ScrollReveal } from '@/components/landing/shared/scroll-reveal';
import { SectionBadge } from '@/components/landing/shared/section-badge';
import { Input } from '@/components/ui/Input';
import { Textarea } from '@/components/ui/Textarea';
import { createContactSchema, type ContactInput } from '@/schemas/contact-schema';

const inputClassName = 'h-11 px-4 hover:bg-transparent';
const textareaClassName = 'min-h-28 px-4 py-3 hover:bg-transparent';

export function ContactSection() {
  const t = useTranslations('landing.contact');
  const tCommon = useTranslations('common');
  const contactSchema = useMemo(
    () =>
      createContactSchema({
        emailInvalid: t('validation.emailInvalid'),
        fullNameRequired: t('validation.fullNameRequired'),
        messageRequired: t('validation.messageRequired'),
        messageTooLong: t('validation.messageTooLong'),
      }),
    [t],
  );
  const [isMessageSent, setIsMessageSent] = useState(false);
  const {
    register,
    handleSubmit,
    reset,
    control,
    formState: { errors },
  } = useForm<ContactInput>({
    resolver: zodResolver(contactSchema),
    defaultValues: {
      fullName: '',
      email: '',
      company: '',
      message: '',
    },
  });

  const message = useWatch({ control, name: 'message' }) ?? '';

  const handleMockSubmit = () => {
    reset();
    setIsMessageSent(true);
  };

  return (
    <section id="contact" className="relative isolate overflow-hidden bg-appBg px-6 py-16 sm:py-24">
      <Image
        src={contactBackground}
        alt=""
        className="pointer-events-none absolute inset-0 -z-10 h-full w-full select-none object-cover"
        aria-hidden="true"
      />

      <div className="relative z-10 mx-auto max-w-7xl">
        <ScrollReveal className="text-center">
          <SectionBadge
            iconName="verified_user"
            className="border-borderGray bg-cardBg px-4 py-2"
            labelClassName="text-xs font-normal text-textGray"
          >
            {t('badge')}
          </SectionBadge>

          <h2 className="mt-6 font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-4xl sm:leading-12 lg:text-[56px] lg:leading-16.25">
            {t.rich('title', {
              highlight: (chunks) => <span className="text-primary">{chunks}</span>,
            })}
          </h2>

          <p className="mx-auto mt-6 max-w-3xl text-lg text-textGray sm:mt-8">{t('description')}</p>

          <div className="mt-8 flex flex-col justify-center gap-4 sm:flex-row">
            <Link
              href="/sign-up"
              className="inline-flex h-10.5 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white shadow-focus-button-glow transition hover:bg-hoverBgPurple"
            >
              {tCommon('startFree')}
            </Link>
            <Link
              href="#"
              className="inline-flex h-10.5 items-center justify-center rounded-lg border border-borderGray bg-surfaceChip px-5 text-sm font-semibold text-white transition hover:bg-hoverBg"
            >
              {tCommon('bookDemo')}
              <span className="material-symbols-rounded ml-2.5" aria-hidden="true">
                arrow_forward
              </span>
            </Link>
          </div>
        </ScrollReveal>

        <div className="mt-12 grid grid-cols-1 items-start gap-8 sm:mt-24 sm:gap-12 lg:grid-cols-2 lg:gap-20">
          <ScrollReveal>
            <SectionBadge
              iconName="alternate_email"
              className="border-borderGray bg-cardBg px-4 py-2"
              labelClassName="text-xs font-normal text-textGray"
            >
              {t('contactUs')}
            </SectionBadge>

            <h3 className="mt-6 max-w-xl font-['Space_Grotesk','Manrope',sans-serif] text-3xl font-bold leading-10 text-white sm:mt-8 sm:text-4xl sm:leading-12 lg:text-[56px] lg:leading-16.25">
              {t.rich('heading', {
                highlight: (chunks) => <span className="text-primary">{chunks}</span>,
                block: (chunks) => <span className="block">{chunks}</span>,
              })}
            </h3>

            <p className="mt-6 max-w-xl border-b border-borderGray pb-6 text-lg text-textGray sm:mt-8 sm:pb-8">
              {t('intro')}
            </p>

            <div className="mt-6 flex flex-col gap-6 sm:mt-8 sm:flex-row sm:items-center sm:gap-12">
              <div className="flex items-center gap-4">
                <span className="flex size-12 items-center justify-center rounded-lg border border-focus/30 bg-focus/5 text-focus">
                  <span className="material-symbols-rounded" aria-hidden="true">
                    mail
                  </span>
                </span>
                <span className="text-sm font-semibold text-white">support@ianua.io</span>
              </div>
              <div className="flex items-center gap-4">
                <span className="flex size-12 items-center justify-center rounded-lg border border-focus/30 bg-focus/5 text-focus">
                  <span className="material-symbols-rounded" aria-hidden="true">
                    location_on
                  </span>
                </span>
                <span className="text-sm font-semibold text-white">{t('location')}</span>
              </div>
            </div>
          </ScrollReveal>

          <ScrollReveal delayMs={140}>
            <form
              className="overflow-hidden rounded-[10px] border border-primary bg-brand-gradient text-left"
              onSubmit={handleSubmit(handleMockSubmit)}
            >
              <div className="flex items-center justify-center px-6 py-3 text-center font-['Space_Grotesk','Manrope',sans-serif] text-xs font-bold uppercase text-appBg">
                {t('form.title')}
              </div>

              <div className="mx-1 mb-1 overflow-hidden rounded-md bg-cardBg">
                <div className="space-y-6 pt-8 pb-6 px-8">
                  <Input
                    {...register('fullName')}
                    className={inputClassName}
                    error={errors.fullName}
                    label={t('form.fullNameLabel')}
                    placeholder={t('form.fullNamePlaceholder')}
                  />

                  <Input
                    {...register('email')}
                    className={inputClassName}
                    error={errors.email}
                    label={t('form.emailLabel')}
                    placeholder={t('form.emailPlaceholder')}
                  />

                  <Input
                    {...register('company')}
                    className={inputClassName}
                    label={t('form.companyLabel')}
                    placeholder={t('form.companyPlaceholder')}
                  />

                  <Textarea
                    {...register('message')}
                    className={textareaClassName}
                    containerClassName="mb-0"
                    error={errors.message}
                    hint={
                      <span className="block text-right">
                        {t('form.characterCount', { count: message.length })}
                      </span>
                    }
                    label={t('form.messageLabel')}
                    maxLength={200}
                    placeholder={t('form.messagePlaceholder')}
                  />
                </div>

                <div className="flex flex-col gap-4 border-t border-borderGray p-6 sm:flex-row sm:items-center sm:justify-between">
                  <div className="space-y-2">
                    <p className="text-xs text-textGray">{t('form.replyTime')}</p>
                    {isMessageSent && (
                      <p
                        className="flex items-center gap-2 text-xs font-medium text-primary"
                        role="status"
                      >
                        <span className="material-symbols-rounded" aria-hidden="true">
                          check_circle
                        </span>
                        {t('form.sent')}
                      </p>
                    )}
                  </div>
                  <button
                    type="submit"
                    className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-focus px-5 text-sm font-semibold text-white transition-colors duration-200 hover:bg-hoverBgPurple"
                  >
                    {t('form.send')}
                    <span className="material-symbols-rounded" aria-hidden="true">
                      arrow_forward
                    </span>
                  </button>
                </div>
              </div>
            </form>

            <p className="mt-5 flex items-center gap-2 text-xs leading-6 text-textGray">
              <span className="material-symbols-rounded mt-0.5 text-primary" aria-hidden="true">
                verified_user
              </span>
              <span>
                {t.rich('form.consent', {
                  privacy: (chunks) => (
                    <Link
                      href="/privacy-policy"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      {chunks}
                    </Link>
                  ),
                  terms: (chunks) => (
                    <Link
                      href="/terms-of-use"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      {chunks}
                    </Link>
                  ),
                })}
              </span>
            </p>
          </ScrollReveal>
        </div>
      </div>
    </section>
  );
}
