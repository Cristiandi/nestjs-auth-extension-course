import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  // Res,
} from '@nestjs/common';
// import { Response } from 'express';

import { Auth } from './decorators/auth.decorator';

import { AuthenticationService } from './authentication.service';

import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { AuthType } from './enums/auth-type-enum';
import { RefreshTokenDto } from './dto/refresh-toke.dto';

@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authenticationService: AuthenticationService) {}

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
}
