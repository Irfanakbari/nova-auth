import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  InternalServerErrorException,
  Inject,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';

import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { Roles } from '../decorators/roles.decorator';
import { AuthService } from '../services/auth.service';

import { AuthUserDto } from '../dto/auth-user.dto';
import type { AuthModuleOptions } from '../options/auth.options';
import { AUTH_ERROR_CODES, AUTH_MODULE_OPTIONS } from '../const/auth.const';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly reflector: Reflector,

    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
  ) {}

  private isExcluded(req: Request, context: ExecutionContext): boolean {
    const { exclude, excludeControllers, excludeModulePrefix } = this.options;
    const path = req.path;
    const method = req.method;
    const controller = context.getClass();

    // 1. Exclude by controller
    if (excludeControllers?.includes(controller)) return true;

    // 2. Exclude by prefix (whole module)
    if (excludeModulePrefix?.some((prefix) => path.startsWith(prefix)))
      return true;

    // 3. Exclude by rules
    for (const rule of exclude ?? []) {
      // A. RegExp rule
      if (rule instanceof RegExp && rule.test(path)) return true;

      // B. wildcard or exact string
      if (typeof rule === 'string') {
        if (rule.endsWith('*') && path.startsWith(rule.slice(0, -1)))
          return true;
        if (path === rule) return true;
      }

      // C. ExcludeRule object
      if (typeof rule === 'object' && ('path' in rule || 'method' in rule)) {
        const pathMatch = (() => {
          if (!rule.path) return true;
          if (rule.path instanceof RegExp) return rule.path.test(path);
          if (rule.path.endsWith('*'))
            return path.startsWith(rule.path.slice(0, -1));
          return path === rule.path;
        })();

        const methodMatch = rule.method
          ? rule.method.toUpperCase() === method.toUpperCase()
          : true;

        if (pathMatch && methodMatch) return true;
      }
    }

    return false;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    // ENTERPRISE EXCLUDE
    if (this.isExcluded(req, context)) return true;

    // 1. Public route
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const token = this.extractTokenFromHeader(req);

    if (!token) {
      throw new UnauthorizedException({
        code: AUTH_ERROR_CODES.MISSING_TOKEN,
        message: 'Missing authorization token',
      });
    }

    // 2. Decode JWT
    let decoded: any;
    try {
      decoded = await this.authService.verifyToken(token);
      if (!decoded) {
        throw new UnauthorizedException({
          code: AUTH_ERROR_CODES.INVALID_TOKEN,
          message: 'Invalid token',
        });
      }
    } catch (err) {
      if (err instanceof UnauthorizedException) throw err;
      throw new InternalServerErrorException({
        code: AUTH_ERROR_CODES.INVALID_TOKEN,
        message: 'Error validating token',
      });
    }

    // 3. Validate payload structure (DTO)
    const dto = plainToInstance(AuthUserDto, {
      sub: decoded.sub,
      name: decoded.name,
      username: decoded.username,
      email: decoded.email,
      sessionId: decoded.sessionId,
      role: Array.isArray(decoded.role) ? decoded.role : [decoded.role],
      azureId: decoded.azureId,
    });

    const errors = validateSync(dto);
    if (errors.length > 0) {
      throw new UnauthorizedException({
        code: AUTH_ERROR_CODES.INVALID_PAYLOAD,
        message: 'Invalid JWT payload format',
      });
    }

    // 4. Session validation (optional)
    const isSessionValid = await this.authService.validateSession(dto);
    if (!isSessionValid) {
      throw new UnauthorizedException({
        code: AUTH_ERROR_CODES.INVALID_TOKEN,
        message: 'Session invalid or expired',
      });
    }

    // Set user to request context
    req['user'] = dto;
    req['accessToken'] = token;

    // 5. Check roles
    const rolesMeta =
      this.reflector.get<string[]>(Roles, context.getHandler()) || null;

    if (!rolesMeta) return true;

    const userRoles = this.authService.aggregateRoles(dto.role);
    const bypassRoles = this.options.bypassRoles ?? [];

    // Super roles bypass
    if (bypassRoles.some((role) => userRoles.includes(role))) return true;

    const hasRole = rolesMeta.some((role) => userRoles.includes(role));
    if (!hasRole) {
      throw new UnauthorizedException({
        code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE,
        message: 'Insufficient role',
      });
    }

    return true;
  }

  private extractTokenFromHeader(req: Request): string | undefined {
    const auth = req.headers.authorization;
    if (!auth) return undefined;
    const [type, token] = auth.split(' ');
    return type === 'Bearer' ? token : undefined;
  }
}
