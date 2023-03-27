import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto, LoginUserDto } from './dto';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import * as bcrypt from 'bcrypt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { JwtService } from '@nestjs/jwt';
import { MailService } from '../mail/mail.service';
import { ChangePasswordDto } from './dto/change-password.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailService,
  ) {}

  // Por defecto usuarios inactivos
  async create(createAuthDto: CreateUserDto) {
    try {
      const { password, ...userData } = createAuthDto;
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = this.userRepository.create({
        ...userData,
        password: hashedPassword,
      });
      const validationToken = await this.createAuthToken(user.email);
      user.validationToken = validationToken;
      await this.userRepository.save(user);
      const confirmationUrl = `${process.env.BASE_URL}/auth/activar-usuario/${validationToken}`;
      const token = this.getJwtToken({ id: user.id });
      await this.mailerService.sendWelcomeEmail({
        email: user.email,
        fullName: user.fullName,
        url_confirmacion: confirmationUrl,
      });
      return {
        ...user,
        token,
      };
    } catch (e) {
      this.handleError(e);
    }
  }

  private getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  private handleError(error: Error): never {
    this.logger.error(error.message, error.stack);
    throw new InternalServerErrorException(
      'Internal Server Error ',
      error.message,
    );
  }

  async login(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'isActivate'],
    });

    if (!user || !bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException(
        'Credenciales inválidas, usuario o contraseña incorrectos',
      );
    }

    if (!user.isActivate) {
      throw new UnauthorizedException(
        `Su cuenta aún no está activada. Por favor, revise su correo electrónico y haga clic en el enlace de confirmación para activar su cuenta. Si no recibió el correo electrónico, revise su carpeta de spam o solicite uno nuevo desde la página de inicio de sesión.`,
      );
    }

    delete user.password;

    return {
      ...user,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  //Metodo para cambiar la contraseña, recibe como argumento el id del usuario,  la contraseña y la nueva contraseña
  async changePassword(id: string, changePasswordDto: ChangePasswordDto) {
    const user = await this.userRepository.findOne({
      where: { id },
      select: ['id', 'email', 'password'],
    });

    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }

    if (!bcrypt.compareSync(changePasswordDto.password, user.password)) {
      throw new UnauthorizedException('Contraseña incorrecta');
    }

    user.password = await bcrypt.hash(changePasswordDto.newPassword, 10);
    await this.userRepository.save(user);
    return {
      ...user,
      token: this.getJwtToken({ id: user.id }),
    };
  }
  // Activar usuario
  async activateUser(token: string) {
    if (!token) {
      throw new BadRequestException('Token no proporcionado');
    }

    const user = await this.userRepository.findOne({
      where: { validationToken: token },
    });

    const isTokenValid = await this.verifyToken(token);

    if (user && isTokenValid) {
      user.isActivate = true;
      user.validationToken = null;
      await this.userRepository.save(user);
      const token = this.getJwtToken({ id: user.id });
      return {
        ...user,
        token,
      };
    } else {
      throw new UnauthorizedException('Token invalido o expirado');
    }
  }

  async checkAuthStatus(user: User) {
    return {
      ...user,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  //Creacion de token para validar usuario
  async createAuthToken(email: string): Promise<string> {
    const payload = { email };
    const options = { expiresIn: '2h' }; // token expira en 2 horas
    return this.jwtService.signAsync(payload, options);
  }

  async verifyToken(token: string): Promise<boolean> {
    try {
      await this.jwtService.verifyAsync(token);
      return true;
    } catch {
      return false;
    }
  }
}
