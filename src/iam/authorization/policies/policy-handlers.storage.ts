import { Injectable, Type } from '@nestjs/common';

import { Policy } from './interfaces/policy.interface';
import { PolicyHandler } from './interfaces/policy-handler.interface';

@Injectable()
export class PolicyHandlersStorage {
  // first argument indicates the type of the key since keys equals classes representing our policies
  // second argument represent values for these keys I'm using any as I'm using policy handler instances
  private readonly collection = new Map<Type<Policy>, PolicyHandler<any>>();

  // for associating the policies with policy handlers
  add<T extends Policy>(policyCls: Type<T>, handler: PolicyHandler<T>) {
    this.collection.set(policyCls, handler);
  }

  // for retriving the policy handler class based on the given policy class
  get<T extends Policy>(policyCls: Type<T>): PolicyHandler<T> | undefined {
    const handler = this.collection.get(policyCls);
    if (!handler) {
      throw new Error(
        `"${policyCls.name}" does not have the associated handler.`,
      );
    }
    return handler;
  }
}
