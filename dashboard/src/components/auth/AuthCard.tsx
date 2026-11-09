'use client';

import { ReactNode } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '../ui/Link';
import { cn } from '@/utils/cn';

type AuthCardProps = {
  children: ReactNode;
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  backToLogin?: boolean;
  backToLoginHref?: string;
  onBackToLogin?: () => void;
  width?: string;
  className?: string;
};

export function AuthCard({
  children,
  title,
  subtitle,
  icon,
  backToLogin = true,
  backToLoginHref = '/login',
  onBackToLogin,
  width,
  className,
}: AuthCardProps) {
  const t = useTranslations('auth.card');

  return (
    <div className={cn('flex w-full flex-col gap-6', width || 'max-w-111')}>
      <div
        className={`bg-cardBg border border-borderGray rounded-[10px] px-6 py-8 ${className || ''}`}
      >
        <div className="mb-6">
          {icon && <div className="mb-4 flex justify-center">{icon}</div>}
          <h1 className="text-2xl font-bold tracking-tight text-center text-white mb-2">{title}</h1>
          {subtitle && <p className="text-center text-sm text-textGray">{subtitle}</p>}
        </div>
        {children}
      </div>
      {backToLogin && (
        <div className="text-center">
          {onBackToLogin ? (
            <button
              type="button"
              onClick={onBackToLogin}
              className="inline-flex items-center justify-center gap-1.5 text-xs font-semibold tracking-widest text-primary transition hover:text-btnWithBgHover"
            >
              <span className="material-symbols-rounded text-base">arrow_back_ios</span>
              {t('backToLogin')}
            </button>
          ) : (
            <Link
              href={backToLoginHref}
              leftIcon={<span className="material-symbols-rounded text-base">arrow_back_ios</span>}
            >
              {t('backToLogin')}
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
