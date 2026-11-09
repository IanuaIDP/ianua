'use client';

import { useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { usePasswordRequirementsHint } from '@/hooks/auth/use-password-requirements-hint';
import { buildResetPasswordSchema, type ResetPasswordInput } from '@/schemas/reset-password-schema';
import type { PasswordPolicy } from '@/types/auth-config';
import { generatePasswordForPolicy } from '@/utils/password-policy';

type ResetMemberPasswordModalMember = {
  email: string;
  name: string;
};

type ResetMemberPasswordModalProps = {
  isSubmitting?: boolean;
  member: ResetMemberPasswordModalMember | null;
  onClose: () => void;
  onSubmit: (data: ResetPasswordInput) => void;
  passwordPolicy: PasswordPolicy;
};

const resetMemberPasswordFormId = 'reset-member-password-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

export function ResetMemberPasswordModal({
  isSubmitting = false,
  member,
  onClose,
  onSubmit,
  passwordPolicy,
}: ResetMemberPasswordModalProps) {
  const t = useTranslations('dashboard.resetPassword');
  const getPasswordHint = usePasswordRequirementsHint();
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const open = Boolean(member);
  const [wasOpen, setWasOpen] = useState(open);
  const passwordSchema = useMemo(
    () => buildResetPasswordSchema(passwordPolicy, getPasswordHint(passwordPolicy)),
    [getPasswordHint, passwordPolicy],
  );
  const {
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<ResetPasswordInput>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { password: '' },
  });

  if (open !== wasOpen) {
    setWasOpen(open);

    if (!open) {
      reset({ password: '' });
      setIsPasswordVisible(false);
    }
  }

  function generatePassword() {
    setValue('password', generatePasswordForPolicy(passwordPolicy), {
      shouldDirty: true,
      shouldValidate: true,
    });
    setIsPasswordVisible(true);
  }

  function handleClose() {
    setIsPasswordVisible(false);
    onClose();
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('submit')}
      primaryActionType="submit"
      primaryActionForm={resetMemberPasswordFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={resetMemberPasswordFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(onSubmit)}
      >
        <Input
          label={t('fullName')}
          placeholder={t('fullNamePlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          value={member?.name ?? ''}
          readOnly
          disabled
        />
        <Input
          label={t('email')}
          placeholder={t('emailPlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          value={member?.email ?? ''}
          readOnly
          disabled
        />
        <Input
          label={t('password')}
          placeholder={t('passwordPlaceholder')}
          type="password"
          isPasswordVisible={isPasswordVisible}
          onPasswordVisibilityChange={setIsPasswordVisible}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          hint={getPasswordHint(passwordPolicy)}
          rightAction={
            <button
              type="button"
              onClick={generatePassword}
              className="flex h-6 items-center gap-2 text-sm font-medium text-primary transition hover:text-btnWithBgHover"
            >
              <span className="material-symbols-rounded">wand_stars</span>
              {t('generate')}
            </button>
          }
          {...register('password')}
          error={errors.password}
        />
      </form>
    </Modal>
  );
}
