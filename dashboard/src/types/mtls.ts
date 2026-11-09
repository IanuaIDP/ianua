export type MtlsMode = 'Disabled' | 'Optional' | 'Required';

export type MtlsConfig = {
  mode: MtlsMode;
  trustedCaCerts: string[];
};
