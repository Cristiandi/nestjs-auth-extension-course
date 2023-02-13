import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';

import { AuthenticationService } from './authentication.service';

import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';

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
}
