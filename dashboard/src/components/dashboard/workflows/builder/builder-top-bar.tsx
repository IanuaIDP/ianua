'use client';

import Link from 'next/link';
import { useTranslations } from 'next-intl';

import { ToolButton } from '@/components/dashboard/workflows/builder/builder-buttons';
import { useBuilderContext } from '@/components/dashboard/workflows/builder/builder-context';
import {
  getSendableGraph,
  hasUnsavedChanges,
} from '@/components/dashboard/workflows/builder/draft-saving';
import { useWorkingCopy } from '@/components/dashboard/workflows/builder/use-working-copy';
import { Button } from '@/components/ui/Button';
import { useNotification } from '@/components/ui/notifications';
import { cn } from '@/utils/cn';

const STATUS_DOTS: Record<string, string> = {
  archived: 'bg-menuHover',
  draft: 'bg-textGray',
  published: 'bg-primary shadow-primary-glow',
};

type BuilderTopBarProps = {
  canPublish: boolean;
  canStartDraft: boolean;
  isOutlineOpen: boolean;
  isStartingDraft: boolean;
  isOlderVersion: boolean;
  onOpenPublish: () => void;
  onStartDraft: () => void;
  onToggleOutline: () => void;
  onTryIt?: () => void;
  workflowId: string | null;
};

function SaveButton() {
  const t = useTranslations('dashboard.workflowBuilder.save');
  const { showNotification } = useNotification();
  const { lookup, save } = useBuilderContext();
  const copy = useWorkingCopy((state) => state.copy);
  const saved = useWorkingCopy((state) => state.saved);
  const editable = useWorkingCopy((state) => state.editable);
  const saveStatus = useWorkingCopy((state) => state.saveStatus);
  const isSaving = saveStatus === 'saving';
  const isUnsaved = hasUnsavedChanges(copy, saved, lookup) || saveStatus === 'failed';

  async function handleSave() {
    await save();

    const state = useWorkingCopy.getState();

    if (state.saveStatus === 'failed') {
      showNotification({ message: state.saveError ?? t('failed'), type: 'error' });

      return;
    }

    const unsent = getSendableGraph(state.copy, state.saved, lookup).unsent.length;

    showNotification({
      message: unsent > 0 ? t('savedExceptUnfinished', { count: unsent }) : t('saved'),
      type: 'success',
    });
  }

  return (
    <Button
      className="ml-2 w-auto py-1.5"
      disabled={!editable || isSaving || !isUnsaved}
      onClick={() => void handleSave()}
      variant="outline"
    >
      {isSaving ? t('saving') : isUnsaved ? t('save') : t('saved')}
    </Button>
  );
}

function SaveState() {
  const t = useTranslations('dashboard.workflowBuilder.save');
  const { lookup } = useBuilderContext();
  const saveStatus = useWorkingCopy((state) => state.saveStatus);
  const saveError = useWorkingCopy((state) => state.saveError);
  const editable = useWorkingCopy((state) => state.editable);
  const copy = useWorkingCopy((state) => state.copy);
  const saved = useWorkingCopy((state) => state.saved);
  const workflowId = useWorkingCopy((state) => state.workflowId);

  if (!editable) {
    return <span>{t('readOnly')}</span>;
  }

  if (saveStatus === 'failed') {
    return <span className="text-error">{saveError ?? t('failed')}</span>;
  }

  if (saveStatus === 'saving' || saveStatus === 'pending') {
    return <span>{t('saving')}</span>;
  }

  if (!workflowId) {
    return <span>{t('notCreated')}</span>;
  }

  const unsent = getSendableGraph(copy, saved, lookup).unsent.length;

  return <span>{unsent > 0 ? t('notSavedYet', { count: unsent }) : t('saved')}</span>;
}

export function BuilderTopBar({
  canPublish,
  canStartDraft,
  isOlderVersion,
  isOutlineOpen,
  isStartingDraft,
  onOpenPublish,
  onStartDraft,
  onToggleOutline,
  onTryIt,
  workflowId,
}: BuilderTopBarProps) {
  const t = useTranslations('dashboard.workflowBuilder.topBar');
  const tStatus = useTranslations('dashboard.workflowBuilder.status');
  const { tenantPathFor } = useBuilderContext();
  const name = useWorkingCopy((state) => state.copy.name);
  const status = useWorkingCopy((state) => state.status);
  const editable = useWorkingCopy((state) => state.editable);
  const change = useWorkingCopy((state) => state.change);
  const remember = useWorkingCopy((state) => state.remember);
  const panel = useWorkingCopy((state) => state.panel);
  const showPanel = useWorkingCopy((state) => state.showPanel);
  const selection = useWorkingCopy((state) => state.selection);
  const statusKey =
    status === 'published' ? 'published' : status === 'archived' ? 'archived' : 'draft';

  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="min-w-0">
        <input
          aria-label={t('name')}
          className="max-w-160 rounded-lg border border-transparent bg-transparent px-1 text-xl font-bold text-white outline-none [field-sizing:content] enabled:hover:bg-hoverBg focus:border-focus"
          disabled={!editable}
          maxLength={100}
          onChange={(event) =>
            change((current) => ({ ...current, name: event.target.value }), false)
          }
          onFocus={remember}
          value={name}
        />
        <div className="mt-0.5 flex items-center gap-2 px-1 text-xs text-textGray">
          <span className={cn('size-2 rounded-full', STATUS_DOTS[statusKey])} />
          <span>{tStatus(statusKey)}</span>
          <span aria-hidden="true">·</span>
          <SaveState />
          {isOlderVersion ? <span className="text-orange">{t('olderVersion')}</span> : null}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1">
        <ToolButton
          aria-expanded={isOutlineOpen}
          icon="format_list_numbered"
          label={t('steps')}
          onClick={onToggleOutline}
          showLabel
        />
        {workflowId ? (
          <Link
            className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-textGray transition hover:bg-hoverBg hover:text-white"
            href={tenantPathFor(`workflows/${workflowId}/runs`)}
          >
            <span className="material-symbols-rounded text-lg!" aria-hidden="true">
              history
            </span>
            {t('runs')}
          </Link>
        ) : null}
        {workflowId ? (
          <Link
            className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-textGray transition hover:bg-hoverBg hover:text-white"
            href={tenantPathFor(`workflows/${workflowId}/evaluations`)}
          >
            <span className="material-symbols-rounded text-lg!" aria-hidden="true">
              fact_check
            </span>
            {t('evaluations')}
          </Link>
        ) : null}
        <ToolButton
          aria-pressed={!selection && panel === 'touches'}
          icon="travel_explore"
          label={t('touches')}
          onClick={() => showPanel('touches')}
          showLabel
        />
        <ToolButton
          aria-pressed={!selection && panel === 'versions'}
          disabled={!workflowId}
          icon="history_edu"
          label={t('versions')}
          onClick={() => showPanel('versions')}
          showLabel
        />
        <ToolButton
          aria-pressed={!selection && panel === 'settings'}
          icon="tune"
          label={t('settings')}
          onClick={() => showPanel('settings')}
          showLabel
        />
        {onTryIt ? (
          <Button className="ml-2 w-auto py-1.5" onClick={onTryIt} variant="outline">
            {t('tryIt')}
          </Button>
        ) : null}
        <SaveButton />
        {canStartDraft ? (
          <Button className="ml-2 w-auto py-1.5" onClick={onStartDraft} isLoading={isStartingDraft}>
            {t('startDraft')}
          </Button>
        ) : null}
        {canPublish ? (
          <Button
            className="ml-2 inline-flex w-auto items-center gap-1.5 py-1.5"
            onClick={onOpenPublish}
          >
            <span className="material-symbols-rounded text-lg!" aria-hidden="true">
              power_settings_new
            </span>
            {t('turnOn')}
          </Button>
        ) : null}
      </div>
    </div>
  );
}
