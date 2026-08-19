import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App, AuthCallback } from "./App";
import type { Phase1Api } from "./api";

function apiWith(systemInfo: Phase1Api["systemInfo"]): Phase1Api {
  return { systemInfo, currentUser: vi.fn() };
}

describe("Phase 1 application shell", () => {
  it("renders the unauthenticated foundation and selectable organization context", async () => {
    render(<App api={apiWith(vi.fn().mockResolvedValue({ name: "Exposure360", version: "0.1.0", phase: 1, api_version: "v1" }))} />);

    expect(await screen.findByText("Sign in securely")).toBeEnabled();
    expect(screen.getByText("System status: available")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Current organization"), "ORG-B");
    expect(screen.getByText("Selected context: ORG-B")).toBeInTheDocument();
  });

  it("shows a safe system error without rendering the raw API failure", async () => {
    render(<App api={apiWith(vi.fn().mockRejectedValue(new Error("postgres password should not render")))} />);

    expect(await screen.findByText("System status: unavailable")).toBeInTheDocument();
    expect(screen.getByText(/Authentication or system status could not be completed/)).toBeInTheDocument();
    expect(screen.queryByText(/postgres password/)).not.toBeInTheDocument();
  });

  it("moves to the loading state when authorization begins", async () => {
    const startAuthorization = vi.fn(() => new Promise<void>(() => undefined));
    render(
      <App
        api={apiWith(vi.fn().mockResolvedValue({ name: "Exposure360", version: "0.1.0", phase: 1, api_version: "v1" }))}
        startAuthorization={startAuthorization}
      />,
    );

    await userEvent.click(await screen.findByText("Sign in securely"));
    expect(startAuthorization).toHaveBeenCalledOnce();
    expect(screen.getByText("Authentication: loading")).toBeInTheDocument();
  });

  it("shows a safe callback error when PKCE state is absent", () => {
    render(<AuthCallback />);

    expect(screen.getByText("Authorization callback")).toBeInTheDocument();
    expect(screen.getByText(/callback state was invalid or incomplete/)).toBeInTheDocument();
  });
});
