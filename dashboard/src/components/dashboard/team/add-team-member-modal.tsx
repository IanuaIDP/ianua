'use client';

import { useEffect, useMemo, useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { useOrgAccess } from '@/hooks/auth/use-org-access';
import { useOrgPasswordPolicy } from '@/hooks/auth/use-password-policy';
import { usePasswordRequirementsHint } from '@/hooks/auth/use-password-requirements-hint';
import { buildAddTeamMemberSchema, type AddTeamMemberInput } from '@/schemas/team-member-schemas';
import { cn } from '@/utils/cn';
import { generatePasswordForPolicy } from '@/utils/password-policy';

type AddTeamMemberModalProps = {
  isSubmitting?: boolean;
  open: boolean;
  orgSlug: string | undefined;
  onClose: () => void;
  onSubmit: (data: AddTeamMemberInput) => void;
};

const addTeamMemberFormId = 'add-team-member-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';

export function AddTeamMemberModal({
  isSubmitting = false,
  open,
  orgSlug,
  onClose,
  onSubmit,
}: AddTeamMemberModalProps) {
  const t = useTranslations('dashboard.addTeamMember');
  const tRoles = useTranslations('dashboard.roles');
  const getPasswordHint = usePasswordRequirementsHint();
  const { assignableRoles } = useOrgAccess();
  const roleOptions = assignableRoles.map((option) => ({
    label: tRoles(option),
    value: option,
  }));
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const passwordPolicy = useOrgPasswordPolicy(orgSlug);
  const passwordSchema = useMemo(
    () => buildAddTeamMemberSchema(passwordPolicy, getPasswordHint(passwordPolicy)),
    [getPasswordHint, passwordPolicy],
  );
  const {
    clearErrors,
    control,
    formState: { errors },
    handleSubmit,
    register,
    reset,
    setValue,
  } = useForm<AddTeamMemberInput>({
    resolver: zodResolver(passwordSchema),
    defaultValues: {
      autoVerify: true,
      email: '',
      fullName: '',
      mode: 'invite',
      password: '',
      role: 'Member',
    },
  });
  const mode = useWatch({ control, name: 'mode' });
  const autoVerify = useWatch({ control, name: 'autoVerify' });
  const role = useWatch({ control, name: 'role' });
  const isCreateMode = mode === 'create';

  useEffect(() => {
    if (!open) {
      reset();
    }
  }, [open, reset]);

  function generatePassword() {
    setValue('password', generatePasswordForPolicy(passwordPolicy), {
      shouldDirty: true,
      shouldValidate: true,
    });
    setIsPasswordVisible(true);
  }

  function handleModeChange(nextMode: AddTeamMemberInput['mode']) {
    clearErrors();
    reset({
      autoVerify,
      email: '',
      fullName: '',
      mode: nextMode,
      password: '',
      role: 'Member',
    });
    setIsPasswordVisible(false);
  }

  function handleClose() {
    setIsPasswordVisible(false);
    onClose();
  }

  function handleFormSubmit(data: AddTeamMemberInput) {
    setIsPasswordVisible(false);
    onSubmit(data);
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={isCreateMode ? t('createMember') : t('sendInvite')}
      primaryActionType="submit"
      primaryActionForm={addTeamMemberFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={addTeamMemberFormId}
        className="flex flex-col gap-4"
        onSubmit={handleSubmit(handleFormSubmit)}
      >
        <div className="grid h-8 grid-cols-2 gap-1 rounded-lg bg-surfaceRaised p-1">
          <button
            type="button"
            onClick={() => handleModeChange('invite')}
            className={cn(
              'rounded-md text-xs font-medium transition',
              !isCreateMode ? 'bg-primary/15 text-primary' : 'text-textGray hover:text-white',
            )}
          >
            {t('sendInvite')}
          </button>
          <button
            type="button"
            onClick={() => handleModeChange('create')}
            className={cn(
              'rounded-md text-xs font-medium transition',
              isCreateMode ? 'bg-primary/15 text-primary' : 'text-textGray hover:text-white',
            )}
          >
            {t('createMember')}
          </button>
        </div>

        <input type="hidden" {...register('mode')} />

        <Input
          label={t('fullName')}
          placeholder={t('fullNamePlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('fullName')}
          error={errors.fullName}
        />
        <Input
          label={t('email')}
          placeholder={t('emailPlaceholder')}
          type="email"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('email')}
          error={errors.email}
        />
        <Select
          label={t('role')}
          options={roleOptions}
          value={role}
          onChange={(value) => setValue('role', value as AddTeamMemberInput['role'])}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          hint={t(`roleHints.${role}`)}
        />

        {isCreateMode ? (
          <>
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

            <div className="border border-borderGray px-4 py-2.5 rounded-[10px] bg-linear-to-r from-surfaceMuted to-cardBg">
              <Switch
                checked={autoVerify}
                label={t('autoVerify')}
                description={t('autoVerifyDescription')}
                onCheckedChange={(value) => setValue('autoVerify', value, { shouldDirty: true })}
              />
            </div>
          </>
        ) : null}
      </form>
    </Modal>
  );
}
