import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Type,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { REQUEST_USER_KEY } from '../../iam.constants';
import { ActiveUserData } from '../../interfaces/active-user-data.interface';
import { POLICIES_KEY } from '../decorators/policies.decorator';
import { Policy } from '../policies/interfaces/policy.interface';
import { PolicyHandlersStorage } from '../policies/policy-handlers.storage';

@Injectable()
export class PoliciesGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly policyHandlersStorage: PolicyHandlersStorage,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // get the policies from the context
    const policies = this.reflector.getAllAndOverride<Policy[]>(POLICIES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // if there are no policies, can activate
    if (!policies) return true;

    // get the user from the context request
    const user: ActiveUserData = context.switchToHttp().getRequest()[
      REQUEST_USER_KEY
    ];

    // handle each policy from the policies array
    await Promise.all(
      policies.map((policy) => {
        const policyHandler = this.policyHandlersStorage.get(
          policy.constructor as Type,
        );
        return policyHandler.handle(policy, user);
      }),
    ).catch((err) => {
      throw new ForbiddenException(err.message);
    });

    return true;
  }
}
