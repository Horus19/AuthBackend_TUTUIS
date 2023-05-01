import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateUserDto {
  @Matches(/^[a-zA-Z0-9_.±]+@correo.uis.edu.co$/, {
    message: 'El correo debe terminar en @correo.uis.edu.co',
  })
  @ApiProperty({
    example: 'correo@correo.uis.edu.co',
    description: 'Correo del usuario',
    uniqueItems: true,
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '123456',
    description: 'Contraseña del usuario',
    minLength: 6,
    maxLength: 50,
  })
  @IsString()
  @MinLength(6)
  @MaxLength(50)
  @Matches(/(?:(?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message:
      'The password must have a Uppercase, lowercase letter and a number',
  })
  password: string;

  @ApiProperty({
    example: 'Juan Perez',
    description: 'Nombre completo del usuario',
  })
  @IsString()
  fullName: string;
}
