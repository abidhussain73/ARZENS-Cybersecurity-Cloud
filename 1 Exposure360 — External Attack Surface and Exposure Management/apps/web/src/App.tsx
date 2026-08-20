import { Component, type ErrorInfo, type ReactNode, useEffect, useState } from "react";
import { type CurrentUser, type Phase1Api, phase1Api } from "./api";
import { Assets } from "./Assets";
import { DiscoveryJobs } from "./DiscoveryJobs";
import { beginAuthorization, validateCallbackState } from "./oidc";
import { ScopeAdmin } from "./ScopeAdmin";

type AuthState = "loading" | "unauthenticated" | "authenticated" | "permission-denied" | "error";
type SystemState = "checking" | "available" | "unavailable";

type AppProps = {
  api?: Phase1Api;
  startAuthorization?: () => Promise<void>;
};

function authLabel(state: AuthState): string {
  return state.replaceAll("-", " ");
}

export function App({ api = phase1Api, startAuthorization = beginAuthorization }: AppProps) {
  if (window.location.pathname.startsWith("/assets")) {
    return <Assets />;
  }
  if (window.location.pathname.startsWith("/settings/scopes")) {
    return <ScopeAdmin />;
  }
  if (window.location.pathname.startsWith("/discovery/jobs")) {
    return <DiscoveryJobs />;
  }
  const [authState, setAuthState] = useState<AuthState>("loading");
  const [systemState, setSystemState] = useState<SystemState>("checking");
  const [organization, setOrganization] = useState("No organization selected");
  const [user, setUser] = useState<CurrentUser | null>(null);

  useEffect(() => {
    let active = true;
    void api
      .systemInfo()
      .then(() => {
        if (active) {
          setSystemState("available");
          setAuthState("unauthenticated");
        }
      })
      .catch(() => {
        if (active) {
          setSystemState("unavailable");
          setAuthState("error");
        }
      });
    return () => {
      active = false;
    };
  }, [api]);

  async function handleLogin(): Promise<void> {
    setAuthState("loading");
    try {
      await startAuthorization();
    } catch {
      setAuthState("error");
    }
  }

  function handleLogout(): void {
    setUser(null);
    setOrganization("No organization selected");
    setAuthState("unauthenticated");
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Exposure360</p>
          <h1>Phase 1 Foundation</h1>
        </div>
        <output aria-live="polite" className={`system-status ${systemState}`}>
          System status: {systemState}
        </output>
      </header>

      <section aria-labelledby="session-heading" className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Identity</p>
            <h2 id="session-heading">Secure application shell</h2>
          </div>
          <output aria-live="polite">Authentication: {authLabel(authState)}</output>
        </div>

        {authState === "unauthenticated" && (
          <p>Sign in through the configured OpenID Connect provider to load an API-verified profile.</p>
        )}
        {authState === "loading" && <p aria-live="polite">Checking session or preparing secure sign in.</p>}
        {authState === "permission-denied" && <p>You are authenticated, but this session lacks the requested organization permission.</p>}
        {authState === "error" && <p>Authentication or system status could not be completed. Try again after the service is available.</p>}

        <div className="action-row">
          <button onClick={() => void handleLogin()} disabled={authState === "loading" || systemState !== "available"}>
            Sign in securely
          </button>
          <button className="secondary" onClick={handleLogout} disabled={authState === "unauthenticated"}>
            Clear local session state
          </button>
        </div>
      </section>

      <section aria-labelledby="context-heading" className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Context</p>
            <h2 id="context-heading">Organization selection</h2>
          </div>
          <span className="foundation-note">Server validation required</span>
        </div>
        <label htmlFor="organization">Current organization</label>
        <select id="organization" value={organization} onChange={(event) => setOrganization(event.target.value)}>
          <option>No organization selected</option>
          <option>ORG-A</option>
          <option>ORG-B</option>
        </select>
        <p aria-live="polite">Selected context: {organization}</p>
      </section>

      <section aria-labelledby="profile-heading" className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Profile</p>
            <h2 id="profile-heading">Current user</h2>
          </div>
        </div>
        {user ? (
          <dl className="profile-grid">
            <div><dt>Name</dt><dd>{user.display_name ?? "Not supplied"}</dd></div>
            <div><dt>Email</dt><dd>{user.email ?? "Not supplied"}</dd></div>
            <div><dt>Memberships</dt><dd>{user.memberships.length}</dd></div>
          </dl>
        ) : (
          <p>Profile details are displayed only after the API verifies an authenticated OpenID Connect session.</p>
        )}
      </section>
    </main>
  );
}

export function AuthCallback() {
  const [validState] = useState(() => validateCallbackState(new URLSearchParams(window.location.search).get("state")));
  const [hasCode] = useState(() => Boolean(new URLSearchParams(window.location.search).get("code")));

  return (
    <main className="app-shell">
      <section aria-labelledby="callback-heading" className="panel">
        <p className="eyebrow">Identity</p>
        <h1 id="callback-heading">Authorization callback</h1>
        {validState && hasCode ? (
          <p>Authorization response received. The browser has validated the PKCE state; a secure server-side session exchange is required before profile data is displayed.</p>
        ) : (
          <p>Authorization could not be completed because the callback state was invalid or incomplete. Return to the application and start sign in again.</p>
        )}
        <a className="return-link" href="/">Return to application shell</a>
      </section>
    </main>
  );
}

type ErrorBoundaryProps = { children: ReactNode };
type ErrorBoundaryState = { failed: boolean };

export class ShellErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  override componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    void error;
    void errorInfo;
  }

  override render(): ReactNode {
    if (this.state.failed) {
      return <main className="app-shell"><section className="panel"><h1>System status unavailable</h1><p>The application shell could not be displayed. Reload the page or contact an authorized operator.</p></section></main>;
    }
    return this.props.children;
  }
}
