'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/modal';
import { Select } from '@/components/ui/Select';
import { CaaValuesField } from '@/components/dashboard/tenant-detail/sections/domains/caa-values-field';
import {
  fieldClassName,
  fieldContainerClassName,
  numberFieldClassName,
} from '@/components/dashboard/tenant-detail/sections/domains/dns-record-form-field-styles';
import { MultiValueField } from '@/components/dashboard/tenant-detail/sections/domains/multi-value-field';
import { MxValuesField } from '@/components/dashboard/tenant-detail/sections/domains/mx-values-field';
import { SrvValuesField } from '@/components/dashboard/tenant-detail/sections/domains/srv-values-field';
import {
  DNS_RECORD_DEFAULT_TTL_SECONDS,
  DNS_RECORD_TTL_MAX_SECONDS,
  DNS_RECORD_TTL_MIN_SECONDS,
  DNS_RECORD_TYPES,
} from '@/constants/dns-record';
import type {
  CaaRecordValue,
  DnsRecord,
  DnsRecordSetInput,
  DnsRecordType,
  MxRecordValue,
  SrvRecordValue,
} from '@/types/dns-record';
import {
  assembleCaaValue,
  assembleMxValue,
  assembleSrvValue,
  emptyCaaValue,
  emptyMxValue,
  emptySrvValue,
  isMultilineRecordType,
  toCaaValues,
  toMultiValues,
  toMxValues,
  toSrvValues,
} from '@/utils/dns-record';

type DnsRecordFormModalProps = {
  isSubmitting?: boolean;
  onClose: () => void;
  onSubmit: (payload: DnsRecordSetInput) => void;
  record?: DnsRecord | null;
  zoneHostname?: string;
};

export function DnsRecordFormModal({
  isSubmitting = false,
  onClose,
  onSubmit,
  record,
  zoneHostname,
}: DnsRecordFormModalProps) {
  const t = useTranslations('dashboard.domains.dns.form');
  const typeOptions = DNS_RECORD_TYPES.map((type) => ({ label: t(`types.${type}`), value: type }));
  const isEditing = Boolean(record);
  const open = record !== undefined;

  const [name, setName] = useState(record?.name ?? '');
  const [recordType, setRecordType] = useState<DnsRecordType>(record?.recordType ?? 'A');
  const [ttlSeconds, setTtlSeconds] = useState(
    String(record?.ttlSeconds ?? DNS_RECORD_DEFAULT_TTL_SECONDS),
  );
  const [singleValue, setSingleValue] = useState(record?.values[0] ?? '');
  const [multiValues, setMultiValues] = useState<string[]>(toMultiValues(record));
  const [mxValues, setMxValues] = useState<MxRecordValue[]>(toMxValues(record));
  const [srvValues, setSrvValues] = useState<SrvRecordValue[]>(toSrvValues(record));
  const [caaValues, setCaaValues] = useState<CaaRecordValue[]>(toCaaValues(record));
  const [formError, setFormError] = useState<string | undefined>(undefined);
  const [wasOpen, setWasOpen] = useState(open);
  const [wasRecordId, setWasRecordId] = useState(
    record ? `${record.name}-${record.recordType}` : '',
  );

  const currentRecordId = record ? `${record.name}-${record.recordType}` : '';

  if (open && (!wasOpen || currentRecordId !== wasRecordId)) {
    setWasOpen(true);
    setWasRecordId(currentRecordId);
    setName(record?.name ?? '');
    setRecordType(record?.recordType ?? 'A');
    setTtlSeconds(String(record?.ttlSeconds ?? DNS_RECORD_DEFAULT_TTL_SECONDS));
    setSingleValue(record?.values[0] ?? '');
    setMultiValues(toMultiValues(record));
    setMxValues(toMxValues(record));
    setSrvValues(toSrvValues(record));
    setCaaValues(toCaaValues(record));
    setFormError(undefined);
  }

  if (!open && wasOpen) {
    setWasOpen(false);
  }

  function handleTypeChange(nextType: string) {
    setRecordType(nextType as DnsRecordType);
    setSingleValue('');
    setMultiValues(['']);
    setMxValues([emptyMxValue()]);
    setSrvValues([emptySrvValue()]);
    setCaaValues([emptyCaaValue()]);
    setFormError(undefined);
  }

  function assembleValues(): string[] | null {
    if (recordType === 'CNAME') {
      return singleValue.trim() ? [singleValue.trim()] : [];
    }

    if (recordType === 'MX') {
      return mxValues.filter((value) => value.host.trim()).map(assembleMxValue);
    }

    if (recordType === 'SRV') {
      return srvValues.filter((value) => value.host.trim()).map(assembleSrvValue);
    }

    if (recordType === 'CAA') {
      return caaValues.filter((value) => value.value.trim()).map(assembleCaaValue);
    }

    return multiValues.map((value) => value.trim()).filter(Boolean);
  }

  function handleSubmit() {
    setFormError(undefined);

    if (!name.trim()) {
      setFormError(t('nameRequired'));
      return;
    }

    const ttl = Number(ttlSeconds);

    if (
      !Number.isInteger(ttl) ||
      ttl < DNS_RECORD_TTL_MIN_SECONDS ||
      ttl > DNS_RECORD_TTL_MAX_SECONDS
    ) {
      setFormError(
        t('ttlInvalid', { max: DNS_RECORD_TTL_MAX_SECONDS, min: DNS_RECORD_TTL_MIN_SECONDS }),
      );
      return;
    }

    const values = assembleValues();

    if (!values || values.length === 0) {
      setFormError(t('valueRequired'));
      return;
    }

    if (recordType === 'CNAME' && values.length > 1) {
      setFormError(t('cnameOne'));
      return;
    }

    onSubmit({
      name: name.trim(),
      recordType,
      ttlSeconds: ttl,
      values,
    });
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEditing ? t('editTitle') : t('addTitle')}
      description={isEditing ? t('editDescription') : t('addDescription')}
      showCloseButton={false}
      primaryActionLabel={isEditing ? t('save') : t('add')}
      onPrimaryAction={handleSubmit}
      isPrimaryActionLoading={isSubmitting}
      isPrimaryActionDisabled={isSubmitting}
    >
      <div className="flex flex-col gap-4">
        <Input
          label={t('name')}
          placeholder={
            zoneHostname ? t('namePlaceholderZone', { zone: zoneHostname }) : 'api.auth.acme.com'
          }
          hint={t('nameHint')}
          containerClassName={fieldContainerClassName}
          className={fieldClassName}
          disabled={isEditing}
          value={name}
          onChange={(event) => setName(event.target.value)}
        />

        <div className="grid grid-cols-2 gap-4">
          <Select
            label={t('type')}
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            disabled={isEditing}
            options={typeOptions}
            value={recordType}
            onChange={handleTypeChange}
          />
          <Input
            label={t('ttl')}
            type="number"
            min={DNS_RECORD_TTL_MIN_SECONDS}
            max={DNS_RECORD_TTL_MAX_SECONDS}
            containerClassName={fieldContainerClassName}
            className={numberFieldClassName}
            value={ttlSeconds}
            onChange={(event) => setTtlSeconds(event.target.value)}
          />
        </div>

        {recordType === 'CNAME' ? (
          <Input
            label={t('value')}
            placeholder="target.example.com"
            hint={t('cnameHint')}
            containerClassName={fieldContainerClassName}
            className={fieldClassName}
            value={singleValue}
            onChange={(event) => setSingleValue(event.target.value)}
          />
        ) : null}

        {recordType === 'A' || recordType === 'AAAA' || recordType === 'TXT' ? (
          <MultiValueField
            isMultiline={isMultilineRecordType(recordType)}
            recordType={recordType}
            values={multiValues}
            onChange={setMultiValues}
          />
        ) : null}

        {recordType === 'MX' ? <MxValuesField values={mxValues} onChange={setMxValues} /> : null}

        {recordType === 'SRV' ? (
          <SrvValuesField values={srvValues} onChange={setSrvValues} />
        ) : null}

        {recordType === 'CAA' ? (
          <CaaValuesField values={caaValues} onChange={setCaaValues} />
        ) : null}

        {formError ? <p className="text-xs text-error">{formError}</p> : null}
      </div>
    </Modal>
  );
}
