import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto } from './dto';
import { AuthGuard } from '@nestjs/passport';
import { GetUser } from './decorators/get-user.decorator';
import { User } from './entities/user.entity';
import { GetRawHeaders } from './decorators/raw-headers.decorator';
import { IncomingHttpHeaders } from 'http2';
import { UserRoleGuard } from './guards/user-role/user-role.guard';
import { RoleProtected } from './decorators/role-protected.decorator';
import { ValidRoles } from './interfaces/valid-roles';
import { Auth } from './decorators/auth.decorator';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ApiParam, ApiProperty, ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiResponse({
    status: 201,
    description: 'Usuario registrado correctamente',
    type: User,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('login')
  @ApiResponse({
    status: 200,
    description: 'Usuario logueado correctamente',
    type: User,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async login(@Body() loginUserDto: LoginUserDto): Promise<LoginResponse> {
    return await this.authService.login(loginUserDto);
  }

  @Get('check-auth-status')
  @Auth()
  checkAuthStatus(@GetUser() user: User) {
    return this.authService.checkAuthStatus(user);
  }

  @Get('activar-usuario/:token')
  @ApiResponse({
    status: 200,
    description: 'Usuario activado correctamente',
    type: User,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized, token invalido' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  @ApiParam({
    name: 'token',
    type: String,
    required: true,
    description: 'Token de validación',
    example: '123456789',
  })
  activarUsuario(@Param('token') token: string) {
    return this.authService.activateUser(token);
  }

  //Método para cambiar contraseña
  @Post('cambiar-contrasena')
  @Auth()
  cambiarContrasena(
    @GetUser() user: User,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(user.id, changePasswordDto);
  }

  /**
   * Peticion para bloquear/desbloquear usuario
   * necesita el id del usuario y un usuario autenticado con el rol de administrador
   * @param id
   * @header Authorization
   * @returns usuario bloqueado/desbloqueado correctamente
   */
  @Post('bloquear-usuario/:id')
  @ApiResponse({
    status: 200,
    description: 'Usuario bloqueado/desbloqueado correctamente',
    type: User,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  @Auth(ValidRoles.ADMIN)
  bloquearUsuario(@Param('id') id: string) {
    return this.authService.blockUser(id);
  }

  // @Get('private')
  // @UseGuards(AuthGuard())
  // testingPrivateRoute(
  //   @GetUser() user: User,
  //   @GetUser('email') email: string,
  //   @GetRawHeaders() rawHeaders: string[],
  //   @Headers() headers: IncomingHttpHeaders,
  // ) {
  //   return {
  //     message: 'This is a private route',
  //     ok: true,
  //     user,
  //     email,
  //     rawHeaders,
  //     headers,
  //   };
  // }

  // @Get('private2')
  // @SetMetadata('roles', ['admin', 'user'])
  // @RoleProtected(ValidRoles.ADMIN, ValidRoles.USER)
  // @UseGuards(AuthGuard(), UserRoleGuard)
  // privateRoute2() {
  //   return {
  //     message: 'This is a private route 2',
  //     ok: true,
  //   };
  // }

  // @Get('private3')
  // @Auth(ValidRoles.ADMIN, ValidRoles.USER)
  // privateRoute3() {
  //   return {
  //     message: 'This is a private route 3',
  //     ok: true,
  //   };
  // }
}
