import { Body, Controller, Get, Headers, Post, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { CreateUserDto, LoginUserDto } from "./dto";
import { AuthGuard } from "@nestjs/passport";
import { GetUser } from "./decorators/get-user.decorator";
import { User } from "./entities/user.entity";
import { GetRawHeaders } from "./decorators/raw-headers.decorator";
import { IncomingHttpHeaders } from "http2";
import { UserRoleGuard } from "./guards/user-role/user-role.guard";
import { RoleProtected } from "./decorators/role-protected.decorator";
import { ValidRoles } from "./interfaces/valid-roles";
import { Auth } from "./decorators/auth.decorator";


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('login')
  login(@Body() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  @Get('check-auth-status')
  @Auth()
  checkAuthStatus(
    @GetUser() user : User,
  ) {
    return this.authService.checkAuthStatus(user);
  }

  @Get('private')
  @UseGuards( AuthGuard() )

  testingPrivateRoute(
    @GetUser() user : User,
    @GetUser('email') email : string,
    @GetRawHeaders() rawHeaders : string[],
    @Headers() headers : IncomingHttpHeaders
  ) {
    return {
      message: 'This is a private route',
      ok: true,
      user,
      email,
      rawHeaders,
      headers
    };

  }


  @Get('private2')
  // @SetMetadata('roles', ['admin', 'user'])
  @RoleProtected( ValidRoles.ADMIN, ValidRoles.USER)
  @UseGuards( AuthGuard(), UserRoleGuard )
  privateRoute2() {
    return {
      message: 'This is a private route 2',
      ok: true,
    };
  }

  @Get('private3')
  @Auth( ValidRoles.ADMIN, ValidRoles.USER)
  privateRoute3() {
    return {
      message: 'This is a private route 3',
      ok: true,
    };
  }

}

