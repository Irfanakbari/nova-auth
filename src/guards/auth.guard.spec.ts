import { Test, TestingModule } from '@nestjs/testing';
import { AuthGuard } from './auth.guard';
import { AuthService } from '../services/auth.service';
import { Reflector } from '@nestjs/core';
import { AUTH_MODULE_OPTIONS } from '../const/auth.const';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

describe('AuthGuard', () => {
  let guard: AuthGuard;
  let authService: jest.Mocked<AuthService>;
  let reflector: jest.Mocked<Reflector>;

  const mockExecutionContext = (
    req: Partial<Request>,
    handler = () => {},
    controller = class {},
  ): ExecutionContext =>
    ({
      switchToHttp: () => ({
        getRequest: () => req,
      }),
      getHandler: () => handler,
      getClass: () => controller,
    }) as any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthGuard,
        {
          provide: AuthService,
          useValue: {
            verifyToken: jest.fn(),
            validateSession: jest.fn(),
            aggregateRoles: jest.fn((roles) => roles),
          },
        },
        {
          provide: Reflector,
          useValue: {
            getAllAndOverride: jest.fn(),
            get: jest.fn(),
          },
        },
        {
          provide: AUTH_MODULE_OPTIONS,
          useValue: {
            exclude: [],
            excludeControllers: [],
            excludeModulePrefix: [],
            bypassRoles: [],
          },
        },
      ],
    }).compile();

    guard = module.get<AuthGuard>(AuthGuard);
    authService = module.get(AuthService);
    reflector = module.get(Reflector);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    it('should return true for public routes', async () => {
      reflector.getAllAndOverride.mockReturnValue(true);
      const context = mockExecutionContext({});
      expect(await guard.canActivate(context)).toBe(true);
    });

    it('should return true for excluded routes', async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AuthGuard,
          { provide: AuthService, useValue: authService },
          { provide: Reflector, useValue: reflector },
          {
            provide: AUTH_MODULE_OPTIONS,
            useValue: { exclude: ['/excluded'] },
          },
        ],
      }).compile();
      guard = module.get<AuthGuard>(AuthGuard);
      const context = mockExecutionContext({ path: '/excluded' });
      expect(await guard.canActivate(context)).toBe(true);
    });

    it('should throw UnauthorizedException if no token is provided', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      const context = mockExecutionContext({ headers: {} });
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for invalid token', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      const context = mockExecutionContext({
        headers: { authorization: 'Bearer invalidtoken' },
      });
      authService.verifyToken.mockRejectedValue(new UnauthorizedException());
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for invalid payload', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      const context = mockExecutionContext({
        headers: { authorization: 'Bearer validtoken' },
      });
      const decodedToken = { sub: '1' }; // Invalid payload
      authService.verifyToken.mockResolvedValue(decodedToken);
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for invalid session', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      const context = mockExecutionContext({
        headers: { authorization: 'Bearer validtoken' },
      });
      const decodedToken = {
        sub: '1',
        name: 'Test User',
        username: 'test',
        email: 'test@test.com',
        sessionId: '123',
        role: ['user'],
      };
      authService.verifyToken.mockResolvedValue(decodedToken);
      authService.validateSession.mockResolvedValue(false);
      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should return true if user has a bypass role', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      reflector.get.mockReturnValue(['user']); // Required roles
      const context = mockExecutionContext({
        headers: { authorization: 'Bearer validtoken' },
      });
      const decodedToken = {
        sub: '1',
        name: 'Test User',
        username: 'test',
        email: 'test@test.com',
        sessionId: '123',
        role: ['superadmin'],
      };
      authService.verifyToken.mockResolvedValue(decodedToken);
      authService.validateSession.mockResolvedValue(true);

      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AuthGuard,
          { provide: AuthService, useValue: authService },
          { provide: Reflector, useValue: reflector },
          {
            provide: AUTH_MODULE_OPTIONS,
            useValue: { bypassRoles: ['superadmin'] },
          },
        ],
      }).compile();
      guard = module.get<AuthGuard>(AuthGuard);

      expect(await guard.canActivate(context)).toBe(true);
    });

    it('should return true if user has required role', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      reflector.get.mockReturnValue(['admin']); // Required roles
      const context = mockExecutionContext({
        headers: { authorization: 'Bearer validtoken' },
      });
      const decodedToken = {
        sub: '1',
        name: 'Test User',
        username: 'test',
        email: 'test@test.com',
        sessionId: '123',
        role: ['admin'],
      };
      authService.verifyToken.mockResolvedValue(decodedToken);
      authService.validateSession.mockResolvedValue(true);

      expect(await guard.canActivate(context)).toBe(true);
    });

    it('should throw UnauthorizedException if user does not have required role', async () => {
      reflector.getAllAndOverride.mockReturnValue(false);
      reflector.get.mockReturnValue(['admin']); // Required roles
      const context = mockExecutionContext({
        headers: { authorization: 'Bearer validtoken' },
      });
      const decodedToken = {
        sub: '1',
        name: 'Test User',
        username: 'test',
        email: 'test@test.com',
        sessionId: '123',
        role: ['user'],
      };
      authService.verifyToken.mockResolvedValue(decodedToken);
      authService.validateSession.mockResolvedValue(true);

      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
