import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';

import jwtConfig from './config/jwt.config';

import { User } from '../users/entities/user.entity';
import { ApiKey } from '../users/api-keys/entities/api-key.entity';

import { AuthenticationGuard } from './authentication/guards/authentication.guard';
import { AccessTokenGuard } from './authentication/guards/access-token.guard';
import { RolesGuard } from './authorization/guards/roles.guard';
import { PermissionsGuard } from './authorization/guards/permissions.guard';
import { PoliciesGuard } from './authorization/guards/policies.guard';

import { HashingService } from './hashing/hashing.service';
import { BcryptService } from './hashing/bcrypt.service';
import { AuthenticationService } from './authentication/authentication.service';
import { PolicyHandlersStorage } from './authorization/policies/policy-handlers.storage';
import { FrameworkContributorPolicyHandler } from './authorization/policies/framework-contributor.policy';

import { RefreshTokenIdsStorage } from './authentication/refresh-token-ids.storage';

import { AuthenticationController } from './authentication/authentication.controller';
import { ApiKeyService } from './authentication/api-keys.service';
import { ApiKeyGuard } from './authentication/guards/api-key.guard';
import { GoogleAuthenticationService } from './authentication/google-authentication.service';
import { GoogleAuthenticationController } from './authentication/google-authentication.controller';
import { OtpAuthenticationService } from './authentication/otp-authentication.service';

@Module({
  imports: [
    ConfigModule.forFeature(jwtConfig),
    TypeOrmModule.forFeature([User, ApiKey]),
    JwtModule.registerAsync(jwtConfig.asProvider()),
  ],
  providers: [
    {
      provide: HashingService,
      useClass: BcryptService,
    },
    // I could have binded access token guard to individual routes instead of doing this globally
    // using the @UseGuards decorator
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard,
    },
    {
      provide: APP_GUARD,
      useClass: PoliciesGuard, // RolesGuard
    },
    AccessTokenGuard,
    ApiKeyGuard,
    RefreshTokenIdsStorage,
    AuthenticationService,
    PolicyHandlersStorage,
    FrameworkContributorPolicyHandler,
    ApiKeyService,
    GoogleAuthenticationService,
    OtpAuthenticationService,
  ],
  controllers: [AuthenticationController, GoogleAuthenticationController],
})
export class IamModule {}
