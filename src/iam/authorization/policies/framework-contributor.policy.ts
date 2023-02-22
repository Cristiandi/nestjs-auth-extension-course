import { Injectable } from '@nestjs/common';
import { ActiveUserData } from '../../interfaces/active-user-data.interface';
import { PolicyHandler } from './interfaces/policy-handler.interface';
import { Policy } from './interfaces/policy.interface';
import { PolicyHandlersStorage } from './policy-handlers.storage';

export class FrameworkContributorPolicy implements Policy {
  name = 'FrameworkContributor';
}

@Injectable()
export class FrameworkContributorPolicyHandler
  implements PolicyHandler<FrameworkContributorPolicy>
{
  constructor(private readonly policyHandlersStorage: PolicyHandlersStorage) {
    this.policyHandlersStorage.add(FrameworkContributorPolicy, this);
  }

  async handle(
    policy: FrameworkContributorPolicy,
    user: ActiveUserData,
  ): Promise<void> {
    const isContributor = user.email.endsWith('@trilion.io');
    if (!isContributor) {
      throw new Error('user is not a contributor');
    }
  }
}
