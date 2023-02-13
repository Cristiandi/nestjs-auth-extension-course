import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { User } from '../../users/entities/user.entity';

import { HashingService } from '../hashing/hashing.service';

import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly hashingService: HashingService,
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

    // TODO: return a JWT
    return true;
  }
}
