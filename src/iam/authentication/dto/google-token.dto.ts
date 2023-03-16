import { IsNotEmpty } from 'class-validator';

export class GoogleTokenDto {
  @IsNotEmpty()
  readonly token: string;
}
