const codeVerifierStorageKey = "exposure360.phase1.pkce.verifier";
const stateStorageKey = "exposure360.phase1.oidc.state";

export type OidcClientConfig = {
  issuerUrl: string;
  clientId: string;
  redirectUri: string;
};

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function randomValue(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function sha256Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

export function oidcClientConfig(): OidcClientConfig {
  const issuerUrl = import.meta.env.VITE_OIDC_ISSUER_URL;
  const clientId = import.meta.env.VITE_OIDC_CLIENT_ID;
  if (!issuerUrl || !clientId) {
    throw new Error("OIDC browser configuration is unavailable.");
  }
  return {
    issuerUrl: issuerUrl.replace(/\/$/, ""),
    clientId,
    redirectUri: `${window.location.origin}/auth/callback`,
  };
}

export async function beginAuthorization(config = oidcClientConfig()): Promise<void> {
  const verifier = randomValue(48);
  const state = randomValue(24);
  const challenge = await sha256Url(verifier);
  sessionStorage.setItem(codeVerifierStorageKey, verifier);
  sessionStorage.setItem(stateStorageKey, state);
  const authorizationUrl = new URL(`${config.issuerUrl}/protocol/openid-connect/auth`);
  authorizationUrl.searchParams.set("client_id", config.clientId);
  authorizationUrl.searchParams.set("redirect_uri", config.redirectUri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", "openid");
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("code_challenge", challenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
  window.location.assign(authorizationUrl.toString());
}

export function validateCallbackState(callbackState: string | null): boolean {
  const expectedState = sessionStorage.getItem(stateStorageKey);
  return Boolean(callbackState && expectedState && callbackState === expectedState);
}
