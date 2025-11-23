import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { AUTH_MODULE_OPTIONS } from '../const/auth.const';
import { AuthModuleOptions } from '../options/auth.options';

describe('AuthService', () => {
  let service: AuthService;
  let jwtService: jest.Mocked<JwtService>;
  let options: AuthModuleOptions;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: JwtService,
          useValue: {
            verify: jest.fn(),
          },
        },
        {
          provide: AUTH_MODULE_OPTIONS,
          useValue: {
            jwtSecret: 'test_secret',
            sessionValidator: jest.fn().mockResolvedValue(true),
            roleAggregator: jest.fn((roles) => (Array.isArray(roles) ? roles : [roles])),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jwtService = module.get(JwtService);
    options = module.get(AUTH_MODULE_OPTIONS);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('verifyToken', () => {
    it('should return decoded token for valid token', () => {
      const decoded = { userId: 1 };
      jwtService.verify.mockReturnValue(decoded);
      expect(service.verifyToken('valid_token')).toEqual(decoded);
      expect(jwtService.verify).toHaveBeenCalledWith('valid_token', { secret: 'test_secret' });
    });

    it('should return false for invalid token', () => {
      jwtService.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });
      expect(service.verifyToken('invalid_token')).toBe(false);
    });
  });

  describe('validateSession', () => {
    it('should return true if no sessionValidator is provided', async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: JwtService, useValue: jwtService },
                { provide: AUTH_MODULE_OPTIONS, useValue: { jwtSecret: 'test_secret' } },
            ],
        }).compile();
        service = module.get<AuthService>(AuthService);
      
        expect(await service.validateSession({} as any)).toBe(true);
    });

    it('should return true if session is valid', async () => {
      const payload = { sub: '1', name: 'Test User', username: 'test', email: 'test@test.com', sessionId: '123', role: ['user'] };
      expect(await service.validateSession(payload)).toBe(true);
      expect(options.sessionValidator).toHaveBeenCalledWith(payload);
    });

    it('should return false if session is invalid', async () => {
      (options.sessionValidator as jest.Mock).mockResolvedValue(false);
      const payload = { sub: '1', name: 'Test User', username: 'test', email: 'test@test.com', sessionId: '123', role: ['user'] };
      expect(await service.validateSession(payload)).toBe(false);
    });
  });

  describe('aggregateRoles', () => {
    it('should use roleAggregator if provided', () => {
        const roles = ['admin', 'user'];
        (options.roleAggregator as jest.Mock).mockReturnValue(['aggregated_role']);
        expect(service.aggregateRoles(roles)).toEqual(['aggregated_role']);
        expect(options.roleAggregator).toHaveBeenCalledWith(roles);
    });

    it('should return array of roles if roleAggregator is not provided', async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: JwtService, useValue: jwtService },
                { provide: AUTH_MODULE_OPTIONS, useValue: { jwtSecret: 'test_secret' } },
            ],
        }).compile();
        service = module.get<AuthService>(AuthService);

        expect(service.aggregateRoles(['admin', 'user'])).toEqual(['admin', 'user']);
        expect(service.aggregateRoles('admin')).toEqual(['admin']);
    });
  });
});
