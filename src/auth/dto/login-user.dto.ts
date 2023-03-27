import { IsEmail, IsString, Matches, MaxLength, MinLength } from "class-validator";

export class LoginUserDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}