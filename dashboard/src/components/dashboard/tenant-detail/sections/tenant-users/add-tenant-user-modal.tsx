'use client';

import { useEffect, useMemo, useState } from 'react';
import { Controller, useForm, useWatch } from 'react-hook-form';
import { useQuery } from '@tanstack/react-query';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { MultiSelect } from '@/components/ui/MultiSelect';
import { Switch } from '@/components/ui/Switch';
import { useTenantPasswordPolicy } from '@/hooks/auth/use-password-policy';
import { usePasswordRequirementsHint } from '@/hooks/auth/use-password-requirements-hint';
import { getApiErrorMessage, getTenantRoles } from '@/lib/api';
import { buildAddTenantUserSchema, type AddTenantUserInput } from '@/schemas/tenant-user-schemas';
import { cn } from '@/utils/cn';
import { generatePasswordForPolicy } from '@/utils/password-policy';

type AddTenantUserModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (data: AddTenantUserInput) => void;
  open: boolean;
  orgSlug?: string;
  tenantSlug: string;
};

const addTenantUserFormId = 'add-tenant-user-form';
const fieldContainerClassName = 'mb-0';
const fieldClassName = 'bg-cardBg';
const emptyRoleIds: string[] = [];

export function AddTenantUserModal({
  isSubmitting = false,
  onClose,
  onSubmit,
  open,
  orgSlug,
  tenantSlug,
}: AddTenantUserModalProps) {
  const t = useTranslations('dashboard.tenantUsers.addModal');
  const tTeam = useTranslations('dashboard.addTeamMember');
  const getPasswordHint = usePasswordRequirementsHint();
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const passwordPolicy = useTenantPasswordPolicy(orgSlug, tenantSlug);
  const passwordSchema = useMemo(
    () => buildAddTenantUserSchema(passwordPolicy, getPasswordHint(passwordPolicy)),
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
  } = useForm<AddTenantUserInput>({
    resolver: zodResolver(passwordSchema),
    defaultValues: {
      autoVerify: true,
      email: '',
      fullName: '',
      mode: 'invite',
      password: '',
      roleIds: emptyRoleIds,
    },
  });
  const {
    data: roles = [],
    error: rolesError,
    isLoading: isLoadingRoles,
  } = useQuery({
    enabled: open && Boolean(orgSlug && tenantSlug),
    queryFn: async () => {
      const response = await getTenantRoles(orgSlug ?? '', tenantSlug, { limit: 100 });

      return response.items;
    },
    queryKey: ['tenant-roles', orgSlug, tenantSlug, 'options'],
  });
  const activeRoleOptions = roles.map((role) => ({ label: role.name, value: role.id }));
  const defaultRoleId = (roles.find((role) => role.isDefault) ?? roles[0])?.id;
  const mode = useWatch({ control, name: 'mode' });
  const autoVerify = useWatch({ control, name: 'autoVerify' });
  const roleIds = useWatch({ control, name: 'roleIds' });
  const isCreateMode = mode === 'create';

  useEffect(() => {
    if (!open) {
      reset();
    }
  }, [open, reset]);

  useEffect(() => {
    if (!open || isLoadingRoles || roleIds.length > 0 || !defaultRoleId) {
      return;
    }

    setValue('roleIds', [defaultRoleId]);
  }, [defaultRoleId, isLoadingRoles, open, roleIds, setValue]);

  function generatePassword() {
    setValue('password', generatePasswordForPolicy(passwordPolicy), {
      shouldDirty: true,
      shouldValidate: true,
    });
    setIsPasswordVisible(true);
  }

  function handleModeChange(nextMode: AddTenantUserInput['mode']) {
    clearErrors();
    reset({
      autoVerify,
      email: '',
      fullName: '',
      mode: nextMode,
      password: '',
      roleIds: emptyRoleIds,
    });
    setIsPasswordVisible(false);
  }

  function handleClose() {
    setIsPasswordVisible(false);
    onClose();
  }

  function handleFormSubmit(data: AddTenantUserInput) {
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
      primaryActionLabel={isCreateMode ? tTeam('createMember') : tTeam('sendInvite')}
      primaryActionType="submit"
      primaryActionForm={addTenantUserFormId}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <form
        id={addTenantUserFormId}
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
            {tTeam('sendInvite')}
          </button>
          <button
            type="button"
            onClick={() => handleModeChange('create')}
            className={cn(
              'rounded-md text-xs font-medium transition',
              isCreateMode ? 'bg-primary/15 text-primary' : 'text-textGray hover:text-white',
            )}
          >
            {tTeam('createMember')}
          </button>
        </div>

        <input type="hidden" {...register('mode')} />

        <Input
          label={tTeam('fullName')}
          placeholder={tTeam('fullNamePlaceholder')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('fullName')}
          error={errors.fullName}
        />
        <Input
          label={tTeam('email')}
          placeholder={tTeam('emailPlaceholder')}
          type="email"
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          {...register('email')}
          error={errors.email}
        />
        <Controller
          control={control}
          name="roleIds"
          render={({ field }) => (
            <MultiSelect
              label={t('role')}
              placeholder={isLoadingRoles ? t('rolesLoading') : t('rolesPlaceholder')}
              containerClassName={fieldContainerClassName}
              className={fieldClassName}
              options={activeRoleOptions}
              value={field.value}
              error={
                errors.roleIds?.message ??
                (rolesError ? getApiErrorMessage(rolesError, t('rolesLoadFailed')) : undefined)
              }
              onChange={field.onChange}
            />
          )}
        />

        {isCreateMode ? (
          <>
            <Input
              label={tTeam('password')}
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
                  {tTeam('generate')}
                </button>
              }
              {...register('password')}
              error={errors.password}
            />

            <div className="border border-borderGray px-4 py-2.5 rounded-[10px] bg-linear-to-r from-surfaceMuted to-cardBg">
              <Switch
                checked={autoVerify}
                label={tTeam('autoVerify')}
                description={tTeam('autoVerifyDescription')}
                onCheckedChange={(value) => setValue('autoVerify', value, { shouldDirty: true })}
              />
            </div>
          </>
        ) : null}
      </form>
    </Modal>
  );
}
