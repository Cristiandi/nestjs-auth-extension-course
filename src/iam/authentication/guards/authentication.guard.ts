import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { AuthType } from '../enums/auth-type-enum';

import { AUTH_TYPE_KEY } from '../decorators/auth.decorator';
import { UnauthorizedException } from '@nestjs/common/exceptions';

import { AccessTokenGuard } from './access-token.guard';
import { ApiKeyGuard } from './api-key.guard';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private static readonly defaultAuthType = AuthType.Bearer;
  private readonly authTypeGuardMap: Record<
    AuthType,
    CanActivate | CanActivate[]
  > = {
    [AuthType.Bearer]: this.accessTokenGuard,
    [AuthType.ApiKey]: this.apiKeyGuard,
    [AuthType.None]: { canActivate: () => true },
  };

  constructor(
    private readonly reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
    private readonly apiKeyGuard: ApiKeyGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    console.log('AuthenticationGuard.canActivate()');

    // getting the auth types from the decorator
    // if no auth types are provided, we default to Bearer
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) ?? [AuthenticationGuard.defaultAuthType];

    // getting the guard instances from the authTypeGuardMap
    const guards = authTypes
      .map((type) => {
        return this.authTypeGuardMap[type];
      })
      .flat();

    let error = new UnauthorizedException();

    // trying to activate each guard
    for (const instance of guards) {
      try {
        const canActivate = await instance.canActivate(context);

        if (canActivate) {
          return true;
        }
      } catch (err) {
        error = err;
      }
    }

    throw error;
  }
}
