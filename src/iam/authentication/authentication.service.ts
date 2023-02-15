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

import jwtConfig from '../config/jwt.config';

import { User } from '../../users/entities/user.entity';

import { ActiveUserData } from '../interfaces/active-user-data.interface';

import { HashingService } from '../hashing/hashing.service';

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

    return await this.generateTokens(existingUser);
  }

  public async generateTokens(user: User) {
    const [accessToken, refreshToken] = await Promise.all([
      this.signToken<Partial<ActiveUserData>>(
        user.id,
        this.jwtConfiguration.accessTokenTtl,
        { email: user.email },
      ),
      this.signToken(user.id, this.jwtConfiguration.refreshTokenTtl),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  public async refreshTokens(input: RefreshTokenDto) {
    const { refreshToken } = input;

    try {
      const { sub } = await this.jwtService.verifyAsync<
        Pick<ActiveUserData, 'sub'>
      >(refreshToken, {
        secret: this.jwtConfiguration.secret,
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
      });

      const existingUser = await this.userRepository.findOneByOrFail({
        id: sub,
      });

      return this.generateTokens(existingUser);
    } catch (error) {
      throw new UnauthorizedException(error);
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
