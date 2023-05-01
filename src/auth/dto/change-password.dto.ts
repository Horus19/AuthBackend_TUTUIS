import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({
    example: '123456',
    description: 'Contraseña del usuario',
  })
  @IsString()
  password: string;

  @ApiProperty({
    example: '123456',
    description: 'Nueva contraseña del usuario',
  })
  @IsString()
  newPassword: string;
}
