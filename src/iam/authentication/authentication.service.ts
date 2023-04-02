import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import { randomUUID } from 'crypto';

import jwtConfig from '../config/jwt.config';

import { User } from '../../users/entities/user.entity';

import { ActiveUserData } from '../interfaces/active-user-data.interface';

import { HashingService } from '../hashing/hashing.service';
import { OtpAuthenticationService } from './otp-authentication.service';

import { RefreshTokenIdsStorage } from './refresh-token-ids.storage';

import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshTokenDto } from './dto/refresh-toke.dto';

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly hashingService: HashingService,
    private readonly jwtService: JwtService,
    private readonly refreshTokenIdsStorage: RefreshTokenIdsStorage,
    private readonly otpAuthenticationService: OtpAuthenticationService,
  ) {}

  public async signUp(input: SignUpDto) {
    const { email, password } = input;

    try {
      const createdUser = this.userRepository.create({
        email,
        password: await this.hashingService.hash(password),
      });

      await this.userRepository.save(createdUser);
    } catch (error) {
      const pgUniqueConstraintErrorCode = '23505';
      if (error.code === pgUniqueConstraintErrorCode) {
        throw new ConflictException();
      }
    }
  }

  public async signIn(input: SignInDto) {
    const { email, password } = input;

    const existingUser = await this.userRepository.findOneBy({
      email,
    });

    if (!existingUser) {
      throw new UnauthorizedException('user does not exist');
    }

    const isEqual = await this.hashingService.compare(
      password,
      existingUser.password,
    );

    if (!isEqual) {
      throw new UnauthorizedException('password is incorrect');
    }
    if (existingUser.isTfaEnabled) {
      console.log('existingUser.tfaSecret', existingUser.tfaSecret);
      console.log('input.tfaCode', input.tfaCode);

      const isValid = this.otpAuthenticationService.verifyCode(
        input.tfaCode,
        existingUser.tfaSecret,
      );

      if (!isValid) {
        throw new UnauthorizedException(
          'invalid two-factor authentication code',
        );
      }
    }

    return await this.generateTokens(existingUser);
  }

  public async generateTokens(user: User) {
    // generate a random refresh token id
    const refreshTokenId = randomUUID();

    // sign the access and refresh tokens
    const [accessToken, refreshToken] = await Promise.all([
      this.signToken<Partial<ActiveUserData>>(
        user.id,
        this.jwtConfiguration.accessTokenTtl,
        {
          email: user.email,
          role: user.role,
          // WARNING
          permissions: user.permissions,
        },
      ),
      this.signToken(user.id, this.jwtConfiguration.refreshTokenTtl, {
        refreshTokenId,
      }),
    ]);

    // store the refresh token id in the storage
    await this.refreshTokenIdsStorage.insert(user.id, refreshTokenId);

    return {
      accessToken,
      refreshToken,
    };
  }

  public async refreshTokens(input: RefreshTokenDto) {
    const { refreshToken } = input;

    try {
      const { sub, refreshTokenId } = await this.jwtService.verifyAsync<
        Pick<ActiveUserData, 'sub'> & { refreshTokenId: string } // this is the payload type
      >(refreshToken, {
        secret: this.jwtConfiguration.secret,
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
      });

      const existingUser = await this.userRepository.findOneByOrFail({
        id: sub,
      });

      // validate the refresh token id
      const isValid = await this.refreshTokenIdsStorage.validate(
        existingUser.id,
        refreshTokenId,
      );

      if (!isValid) {
        throw new Error('refresh token is invalid');
      }

      // if the token is valid, invalidate it
      await this.refreshTokenIdsStorage.invalidate(existingUser.id);

      return this.generateTokens(existingUser);
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }

  private async signToken<T>(userId: number, expiresIn: number, payload?: T) {
    return await this.jwtService.signAsync(
      {
        sub: userId,
        ...payload,
      },
      {
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
        secret: this.jwtConfiguration.secret,
        expiresIn: expiresIn,
      },
    );
  }
}
