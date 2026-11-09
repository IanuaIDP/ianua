export function isValidEmail(value: string | null) {
  return Boolean(value && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value));
}
