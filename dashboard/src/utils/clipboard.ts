function copyWithTextArea(value: string) {
  const textArea = document.createElement('textarea');

  textArea.value = value;
  textArea.setAttribute('readonly', '');
  textArea.style.position = 'fixed';
  textArea.style.opacity = '0';
  document.body.append(textArea);
  textArea.select();

  try {
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    textArea.remove();
  }
}

/**
 * Puts `value` on the clipboard and says whether it worked. A plain `http://`
 * address has no clipboard API, so the older copy command is tried there.
 */
export async function writeToClipboard(value: string) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      return copyWithTextArea(value);
    }
  }

  return copyWithTextArea(value);
}
