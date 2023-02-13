import { IsEmail, MinLength } from 'class-validator';

export class SignInDto {
  @IsEmail()
  readonly email: string;

  @MinLength(10)
  readonly password: string;
}
