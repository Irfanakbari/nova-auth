import { AuthUser } from '../interfaces/auth.interface';

export interface ExcludeRule {
  path?: string | RegExp;
  method?: string; // GET, POST, etc
}

export interface AuthModuleOptions {
  jwtSecret: string;
  bypassRoles?: string[];
  roleAggregator?: (roles: string[] | string) => string[];
  sessionValidator?: (payload: AuthUser) => Promise<boolean> | boolean;

  /** enterprise-level exclude system */
  exclude?: (string | RegExp | ExcludeRule)[];
  excludeControllers?: Function[]; // e.g. [HealthController]
  excludeModulePrefix?: string[]; // e.g. ['/health', '/public']
}
