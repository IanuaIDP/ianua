export function formatStatusLabel(status: string): string {
  return status.replace(/([a-z])([A-Z])/g, '$1 $2');
}
