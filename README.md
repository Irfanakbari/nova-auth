# Nova Auth

**Nova Auth** is a comprehensive authentication and authorization solution designed for modern NestJS applications. In today's development landscape, securing endpoints and managing user access are critical but often complex tasks. Developers need a reliable, flexible, and easy-to-integrate system that doesn't compromise on power or scalability.

This module provides a robust, JWT-based security layer that simplifies protecting your API. By leveraging NestJS's core concepts like Guards and Decorators, Nova Auth offers an intuitive and declarative API for managing access control. Whether you're building a simple application with public and private routes or a large-scale enterprise system with complex role hierarchies and granular access rules, Nova Auth provides the tools you need.

Our goal is to provide a seamless developer experience, allowing you to secure your application with minimal configuration while offering powerful customization options for advanced use cases. From validating session integrity to aggregating user roles and defining sophisticated exclusion rules, Nova Auth is engineered to be the backbone of your application's security model.

## Features

-   JWT-based authentication
-   Role-based access control (RBAC)
-   `@User()` decorator to access authenticated user details
-   Public and protected routes
-   Bypass roles for superusers
-   Extensible session validation
-   Customizable error responses
-   Enterprise-level exclusion system for routes

## Installation

```bash
npm install @irfanakbari/nova-auth
```

## How to Import

To use the `AuthModule`, you need to import it into your application's root module.

### Basic Configuration

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@irfanakbari/nova-auth';

@Module({
  imports: [
    AuthModule.register({
      jwtSecret: process.env.JWT_SECRET || 'changeme',
    }),
  ],
})
export class AppModule {}
```

### Advanced Configuration

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@irfanakbari/nova-auth';
import { HealthController } from './health.controller';

@Module({
  imports: [
    AuthModule.register({
      jwtSecret: process.env.JWT_SECRET || 'changeme',
      bypassRoles: ['SUPER', 'MGR_IT'],
      // optional: add a session validator that checks Redis/DB
      sessionValidator: async (payload) => {
        // Example: check sessionId exist in your session store
        return true;
      },
      // optional: aggregate roles
      roleAggregator: (roles) => (Array.isArray(roles) ? roles : [roles]).map(r => r.toUpperCase()),

      // --- Enterprise-level exclude system ---
      // Exclude specific controllers from authentication
      excludeControllers: [HealthController],
      // Exclude all routes under a specific module prefix
      excludeModulePrefix: ['/health', '/public'],
      // Exclude routes by path, regex, or method
      exclude: [
        '/specific-path', // exclude a specific path
        /^\/api\/v1\/public\//, // exclude paths matching a regex
        { path: '/users', method: 'POST' } // exclude a path with a specific method
      ],
    }),
  ],
})
export class AppModule {}
```

## Required JWT Payload Format

The JWT payload must contain the following fields:

```typescript
interface JwtPayload {
  sub: string;
  name: string;
  username: string;
  email?: string;
  sessionId?: string;
  role: string[];
  azureId?: string;
}
```

-   `sub`: The subject of the token (usually the user ID).
-   `name`: The user's full name.
-   `username`: The user's username.
-   `email` (optional): The user's email address.
-   `sessionId` (optional): The session ID.
-   `role`: An array of roles associated with the user.
-   `azureId` (optional): The user's Azure Active Directory ID.

## How to Access User DTO

After a user is authenticated, the `AuthGuard` attaches the user's information to the request object. You can access it in your controllers using the `@User()` decorator.

```typescript
// me.controller.ts
import { Controller, Get } from '@nestjs/common';
import { User, AuthUserDto } from '@irfanakbari/nova-auth';

@Controller('me')
export class MeController {
  @Get()
  getMe(@User() user: AuthUserDto) {
    return user;
  }

  @Get('email')
  getEmail(@User('email') email: string) {
    return { email };
  }
}
```

## Sample Usage

Once the `AuthModule` is imported, you can use the `AuthGuard` to protect your routes. By default, all routes are protected. You can use the `@Public()` decorator to make a route accessible to everyone.

To restrict a route to specific roles, you can use the `@Roles()` decorator.

```typescript
// your.controller.ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard, Public, Roles } from '@irfanakbari/nova-auth';

@Controller('items')
@UseGuards(AuthGuard) // Protect all routes in this controller
export class ItemsController {
  @Get()
  @Roles('USER') // Only users with the 'USER' role can access this route
  findAll() {
    return 'This is a protected route for users.';
  }

  @Get('public')
  @Public() // This route is public
  findPublic() {
    return 'This is a public route.';
  }

  @Get('admin')
  @Roles('ADMIN') // Only users with the 'ADMIN' role can access this route
  findForAdmin() {
    return 'This is a protected route for admins.';
  }
}
```

## Sample Unauthorized Response

If a user tries to access a protected route without a valid token or sufficient permissions, the module will return an `UnauthorizedException` with a specific error code and message.

### Missing Token

```json
{
  "statusCode": 401,
  "message": "Missing authorization token",
  "code": "MISSING_TOKEN"
}
```

### Invalid Token

```json
{
  "statusCode": 401,
  "message": "Invalid token",
  "code": "INVALID_TOKEN"
}
```

### Insufficient Role

```json
{
  "statusCode": 401,
  "message": "Insufficient role",
  "code": "INSUFFICIENT_ROLE"
}
```
