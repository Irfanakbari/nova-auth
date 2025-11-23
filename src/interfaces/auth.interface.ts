export interface AuthUser {
  sub: string;
  name: string;
  username: string;
  email?: string;
  sessionId?: string;
  role: string[] | string;
  azureId?: string;
}