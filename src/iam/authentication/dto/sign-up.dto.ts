import { IsEmail, MinLength } from 'class-validator';

export class SignUpDto {
  @IsEmail()
  readonly email: string;

  @MinLength(10)
  readonly password: string;
}
