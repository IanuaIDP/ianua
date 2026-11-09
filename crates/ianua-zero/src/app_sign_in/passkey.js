"use strict";

// Signs in with a passkey from the gateway's login page. It is the one
// script a gateway page runs: served by the gateway at a fixed address the
// page's policy names, never inline, and it talks only to the page's own
// passkey address. Without passkey support in the browser the button stays
// hidden and the page works as before.
(() => {
  const button = document.getElementById("passkey");
  if (!button || !window.PublicKeyCredential || !navigator.credentials) {
    return;
  }

  const address = button.dataset.address;
  const returnTo = button.dataset.returnTo;

  const fromBase64Url = (text) => {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  };

  const toBase64Url = (bytes) => {
    let binary = "";
    new Uint8Array(bytes).forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const post = async (body) => {
    const response = await fetch(address, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    return response.json();
  };

  const refused = (code) => {
    const query = new URLSearchParams({ error: code || "failed" });
    if (returnTo) {
      query.set("return_to", returnTo);
    }
    window.location.assign(window.location.pathname + "?" + query.toString());
  };

  const requestOptions = (challenge) => {
    const decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(challenge)));
    const options = decoded.publicKey;
    options.challenge = fromBase64Url(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map((allowed) => ({
      ...allowed,
      id: fromBase64Url(allowed.id),
    }));
    return options;
  };

  const answerOf = (credential) => {
    const response = credential.response;
    const answer = {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: toBase64Url(response.authenticatorData),
        clientDataJSON: toBase64Url(response.clientDataJSON),
        signature: toBase64Url(response.signature),
        userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
      },
      extensions: credential.getClientExtensionResults(),
    };
    return toBase64Url(new TextEncoder().encode(JSON.stringify(answer)));
  };

  const signIn = async () => {
    const email = document.getElementById("email");
    const typed = email && email.value ? { email: email.value } : {};
    const challenge = await post(typed);
    if (!challenge.ceremony_id) {
      refused(challenge.error);
      return;
    }
    let credential;
    try {
      credential = await navigator.credentials.get({
        publicKey: requestOptions(challenge.challenge),
      });
    } catch (error) {
      if (error && error.name === "NotAllowedError") {
        return;
      }
      refused("failed");
      return;
    }
    if (!credential) {
      return;
    }
    const answered = await post({
      ceremony_id: challenge.ceremony_id,
      credential_id: toBase64Url(credential.rawId),
      response: answerOf(credential),
      return_to: returnTo,
    });
    if (!answered.signed_in) {
      refused(answered.error);
      return;
    }
    window.location.assign(answered.hop_to || answered.return_to || "/");
  };

  button.hidden = false;
  button.addEventListener("click", () => {
    button.disabled = true;
    signIn()
      .catch(() => refused("failed"))
      .finally(() => {
        button.disabled = false;
      });
  });
})();
