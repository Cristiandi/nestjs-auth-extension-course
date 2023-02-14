import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { AuthType } from '../enums/auth-type-enum';

import { AUTH_TYPE_KEY } from '../decorators/auth.decorator';

import { AccessTokenGuard } from './access-token.guard';
import { UnauthorizedException } from '@nestjs/common/exceptions';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private static readonly defaultAuthType = AuthType.Bearer;
  private readonly authTypeGuardMap: Record<
    AuthType,
    CanActivate | CanActivate[]
  > = {
    [AuthType.Bearer]: this.accessTokenGuard,
    [AuthType.None]: { canActivate: () => true },
  };

  constructor(
    private readonly reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) ?? [AuthenticationGuard.defaultAuthType];

    console.log('authTypes', authTypes);

    const guards = authTypes
      .map((type) => {
        return this.authTypeGuardMap[type];
      })
      .flat();

    console.log('guards', guards);

    let error = new UnauthorizedException();

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
