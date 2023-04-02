import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { authenticator } from 'otplib';

import { User } from '../../users/entities/user.entity';

@Injectable()
export class OtpAuthenticationService {
  constructor(
    private readonly configService: ConfigService,
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  public generateSecret(email: string) {
    const appName = this.configService.get('TFA_APP_NAME');

    const secret = authenticator.generateSecret();

    const uri = authenticator.keyuri(email, appName, secret);

    return {
      uri,
      secret,
    };
  }

  public verifyCode(code: string, secret: string) {
    return authenticator.verify({ token: code, secret });
  }

  public async enableTfaForUser(email: string, secret: string) {
    const { id } = await this.userRepository.findOneByOrFail({ email });

    await this.userRepository.update(
      { id },
      // TIP: Ideally, we would want to encrypt the "secret" instead of
      // storing it in a plaintext. Note - we couldn't use hashing here as
      // the original secret is required to verify the user's provided code.
      {
        isTfaEnabled: true,
        tfaSecret: secret,
      },
    );
  }
}
