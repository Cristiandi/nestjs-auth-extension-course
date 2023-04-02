import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
  // Res,
} from '@nestjs/common';
import { Response } from 'express';
import { toFileStream } from 'qrcode';

import { Auth } from './decorators/auth.decorator';
import { ActiveUser } from '../decorators/active-user.decorator';

import { AuthenticationService } from './authentication.service';
import { OtpAuthenticationService } from './otp-authentication.service';

import { AuthType } from './enums/auth-type-enum';

import { ActiveUserData } from '../interfaces/active-user-data.interface';

import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshTokenDto } from './dto/refresh-toke.dto';

@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
  constructor(
    private readonly authenticationService: AuthenticationService,
    private readonly otpAuthenticationService: OtpAuthenticationService,
  ) {}

  @Post('sign-up')
  signUp(@Body() input: SignUpDto) {
    return this.authenticationService.signUp(input);
  }

  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  signIn(@Body() input: SignInDto) {
    return this.authenticationService.signIn(input);
  }

  /*
  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(
    @Res({ passthrough: true }) response: Response,
    @Body() input: SignInDto,
  ) {
    const accessToken = await this.authenticationService.signIn(input);

    response.cookie('access_token', accessToken, {
      secure: true,
      httpOnly: true,
      sameSite: true,
    });
  }
  */

  @HttpCode(HttpStatus.OK)
  @Post('refresh-tokens')
  refreshTokens(@Body() input: RefreshTokenDto) {
    return this.authenticationService.refreshTokens(input);
  }

  @Auth(AuthType.Bearer)
  @HttpCode(HttpStatus.OK)
  @Post('2fa/generate')
  async generateQrCode(
    @ActiveUser() activeUser: ActiveUserData,
    @Res() response: Response,
  ) {
    const { secret, uri } = this.otpAuthenticationService.generateSecret(
      activeUser.email,
    );

    await this.otpAuthenticationService.enableTfaForUser(
      activeUser.email,
      secret,
    );

    response.type('png');

    return toFileStream(response, uri);
  }
}
