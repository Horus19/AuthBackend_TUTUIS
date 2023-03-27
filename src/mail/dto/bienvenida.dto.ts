import { IsEmail, IsString } from 'class-validator';

export class BienvenidaDto {
  @IsEmail()
  email: string;

  @IsString()
  fullName: string;

  @IsString()
  url_confirmacion: string;
}
