import { createRoot } from "react-dom/client";
import { App, AuthCallback, ShellErrorBoundary } from "./App";
import "./styles.css";

const page = window.location.pathname === "/auth/callback" ? <AuthCallback /> : <App />;
createRoot(document.getElementById("root")!).render(<ShellErrorBoundary>{page}</ShellErrorBoundary>);
