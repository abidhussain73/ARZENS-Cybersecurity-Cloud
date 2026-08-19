export type SystemInfo = {
  name: string;
  version: string;
  phase: number;
  api_version: string;
};

export type CurrentUser = {
  id: string;
  subject: string;
  display_name: string | null;
  email: string | null;
  memberships: Array<{
    organization_id: string;
    organization_name: string;
    role: string;
  }>;
};

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, accessToken?: string): Promise<T> {
  const init: RequestInit = {};
  if (accessToken) {
    init.headers = { Authorization: `Bearer ${accessToken}` };
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    throw new ApiError(response.status, "The service could not complete the request.");
  }
  return (await response.json()) as T;
}

export interface Phase1Api {
  systemInfo(): Promise<SystemInfo>;
  currentUser(accessToken: string): Promise<CurrentUser>;
}

export const phase1Api: Phase1Api = {
  systemInfo: () => request<SystemInfo>("/api/v1/system/info"),
  currentUser: (accessToken) => request<CurrentUser>("/api/v1/me", accessToken),
};
