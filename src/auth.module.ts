import { Module, DynamicModule } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { AuthService } from './services/auth.service';
import { AuthGuard } from './guards/auth.guard';
import { AuthModuleOptions } from './options/auth.options';
import { AUTH_MODULE_OPTIONS } from './const/auth.const';

@Module({})
export class AuthModule {
  static register(options: AuthModuleOptions): DynamicModule {
    if (!options || !options.jwtSecret) {
      throw new Error('AuthModule.register requires jwtSecret in options');
    }

    const providerOptions = {
      provide: AUTH_MODULE_OPTIONS,
      useValue: {
        bypassRoles: options.bypassRoles ?? ['SUPER'],
        jwtSecret: options.jwtSecret,
        roleAggregator: options.roleAggregator,
        sessionValidator: options.sessionValidator,
        exclude: options.exclude,
        excludeControllers: options.excludeControllers,
        excludeModulePrefix: options.excludeModulePrefix,
      },
    };

    return {
      module: AuthModule,
      imports: [JwtModule.register({ secret: options.jwtSecret })],
      providers: [
        providerOptions,
        AuthService,
        {
          provide: APP_GUARD,
          useClass: AuthGuard,
        },
      ],
      exports: [AuthService],
    };
  }
}