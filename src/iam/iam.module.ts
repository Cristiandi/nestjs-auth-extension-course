import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';

import jwtConfig from './config/jwt.config';
import { User } from '../users/entities/user.entity';

import { AuthenticationGuard } from './authentication/guards/authentication.guard';
import { AccessTokenGuard } from './authentication/guards/access-token.guard';
import { RolesGuard } from './authorization/guards/roles.guard';

import { HashingService } from './hashing/hashing.service';
import { BcryptService } from './hashing/bcrypt.service';
import { AuthenticationService } from './authentication/authentication.service';

import { RefreshTokenIdsStorage } from './authentication/refresh-token-ids.storage';

import { AuthenticationController } from './authentication/authentication.controller';

@Module({
  imports: [
    ConfigModule.forFeature(jwtConfig),
    TypeOrmModule.forFeature([User]),
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
      useClass: RolesGuard,
    },
    AccessTokenGuard,
    RefreshTokenIdsStorage,
    AuthenticationService,
  ],
  controllers: [AuthenticationController],
})
export class IamModule {}
