'use client';

import { useTranslations } from 'next-intl';

import { Modal } from '@/components/ui/modal';
import type { Tool } from '@/types/tool';

type ToolSchemaModalProps = {
  onClose: () => void;
  tool: Tool | null;
};

export function ToolSchemaModal({ onClose, tool }: ToolSchemaModalProps) {
  const t = useTranslations('dashboard.tools.schemaModal');

  return (
    <Modal
      open={Boolean(tool)}
      onClose={onClose}
      title={t('title')}
      description={t('description')}
      showCloseButton={false}
      primaryActionLabel={t('close')}
      onPrimaryAction={onClose}
      showCancelButton={false}
    >
      <pre className="max-h-96 overflow-auto rounded-lg border border-borderGray bg-surfaceInset px-4 py-2.5 font-mono text-[10px] leading-relaxed text-white">
        {JSON.stringify(tool?.schema ?? {}, null, 2)}
      </pre>
    </Modal>
  );
}
