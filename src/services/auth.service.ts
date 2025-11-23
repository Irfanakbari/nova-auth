import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AUTH_MODULE_OPTIONS } from '../const/auth.const';
import * as authOptions from '../options/auth.options';
import { AuthUser } from '../interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: authOptions.AuthModuleOptions,
  ) {}

  verifyToken(token: string): any | false {
    try {
      return this.jwtService.verify(token, { secret: this.options.jwtSecret });
    } catch {
      return false;
    }
  }

  async validateSession(payload: AuthUser): Promise<boolean> {
    if (!this.options.sessionValidator) return true;
    const result = await this.options.sessionValidator(payload);
    return !!result;
  }

  aggregateRoles(rawRoles: string[] | string): string[] {
    if (this.options.roleAggregator)
      return this.options.roleAggregator(rawRoles);
    return Array.isArray(rawRoles) ? rawRoles : [rawRoles];
  }
}