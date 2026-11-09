'use client';

import Image, { type StaticImageData } from 'next/image';
import { useTranslations } from 'next-intl';

import githubIcon from '@/assets/icons/github.png';
import googleIcon from '@/assets/icons/google.svg';
import { SocialButtonProvider } from '@/types/auth';

type SocialButtonProps = {
  disabled?: boolean;
  isLoading?: boolean;
  provider: SocialButtonProvider;
  onClick?: () => void;
};

export function SocialButton({
  disabled = false,
  isLoading = false,
  provider,
  onClick,
}: SocialButtonProps) {
  const t = useTranslations('auth.social');
  const icons: Record<Exclude<SocialButtonProvider, 'passkey'>, StaticImageData> = {
    google: googleIcon,
    github: githubIcon,
  };

  const labels = {
    google: 'Google',
    github: 'GitHub',
    passkey: t('passkey'),
  };

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || isLoading}
      className="w-full h-10.5 flex items-center justify-center gap-2.5 px-4 border border-borderGray rounded-lg text-sm font-semibold hover:bg-hoverBg transition duration-200 disabled:pointer-events-none disabled:opacity-50"
    >
      {provider === 'passkey' ? (
        <span className="material-symbols-rounded text-textGray">key</span>
      ) : (
        <Image
          src={icons[provider]}
          alt=""
          width={20}
          height={20}
          className="size-5 object-contain"
        />
      )}
      {isLoading ? t('signingIn') : labels[provider]}
    </button>
  );
}
