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
import { ChangePasswordDto } from './dto/change-password.dto';

import { RabbitMQService } from './rabbit-mq/rabbit-mq.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly rabbitMQService: RabbitMQService,
  ) {}

  /**
   * Metodo asincrono encargado de crear un nuevo usuario en la base de datos
   *  y enviar un correo electrónico de bienvenida al usuario recién registrado.
   * @param createAuthDto
   * @returns Usuario creado y token de autenticación
   */
  async create(createAuthDto: CreateUserDto) {
    try {
      const { password, ...userData } = createAuthDto;
      const hashedPassword = await bcrypt.hash(password, 10);
      const user: User = this.userRepository.create({
        ...userData,
        password: hashedPassword,
      });
      const validationToken = await this.createAuthToken(user.email);
      user.validationToken = validationToken;
      await this.userRepository.save(user);
      const confirmationUrl = `http://${process.env.BASE_URL}/auth/activar-usuario/${validationToken}`;
      const token = this.getJwtToken({ id: user.id });
      await this.rabbitMQService.sendMessage(
        'send-welcome-email',
        JSON.stringify({
          email: user.email,
          fullName: user.fullName,
          url_confirmacion: confirmationUrl,
        }),
      );
      return {
        ...user,
        token,
      };
    } catch (e) {
      this.handleError(e);
    }
  }

  /**
   *
   * @param payload
   * @returns
   */
  getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  /**
   *
   * @param error
   */
  private handleError(error: Error): never {
    this.logger.error(error.message, error.stack);
    throw new InternalServerErrorException(
      'Internal Server Error ',
      error.message,
    );
  }

  ///Metodo para manejar el login
  async login(loginUserDto: LoginUserDto): Promise<LoginResponse> {
    const { email, password } = loginUserDto;

    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password', 'isActivate', 'fullName', 'roles'],
    });

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return {
        ok: false,
        message: 'Credenciales inválidas, usuario o contraseña incorrectos',
      };
    }

    if (!user.isActivate) {
      return {
        ok: false,
        message: `Su cuenta aún no está activada. Por favor, revise su correo electrónico y haga clic en el enlace de confirmación para activar su cuenta. Si no recibió el correo electrónico, revise su carpeta de spam o solicite uno nuevo desde la página de inicio de sesión.`,
      };
    }

    delete user.password;

    return {
      ok: true,
      ...user,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  /**
   * Metodo para cambiar la contraseña del usuario
   * @param id
   * @param changePasswordDto
   * @returns usuario con la contraseña cambiada
   */
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

  /**
   * Metodo para activar el usuario
   * @param token
   * @returns usuario activado
   */
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

  /**
   *  Metodo encargado de bloquear o desbloquear un usuario
   * @param id
   * @returns usuario bloqueado/desbloqueado
   */
  async blockUser(id: string) {
    const user = await this.userRepository.findOne({
      where: { id },
    });
    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }
    user.isBlocked = !user.isBlocked;
    await this.userRepository.save(user);
    return {
      ...user,
    };
  }

  ///Metodo para verificar el estado de la autenticacion
  async checkAuthStatus(user: User) {
    return {
      ok: true,
      ...user,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  ///Metodo para crear el token de validacion
  async createAuthToken(email: string): Promise<string> {
    const payload = { email };
    const options = { expiresIn: '2h' }; // token expira en 2 horas
    return this.jwtService.signAsync(payload, options);
  }

  ///Metodo para verificar el token
  async verifyToken(token: string): Promise<boolean> {
    try {
      await this.jwtService.verifyAsync(token);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Envia un correo electrónico al usuario con una nueva contraseña generada aleatoriamente.
   * @param email
   */
  async forgotPassword(email: string) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }

    const newPassword = this.generateRandomPassword();
    user.password = await bcrypt.hash(newPassword, 10);
    await this.userRepository.save(user);

    await this.rabbitMQService.sendMessage(
      'send-forgot-password-email',
      JSON.stringify({
        email: user.email,
        fullName: user.fullName,
        newPassword,
      }),
    );
  }

  /**
   * Genera una contraseña aleatoria.
   * @returns contraseña aleatoria
   * @private
   */
  private generateRandomPassword() {
    const length = 8;
    const characters =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let password = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      password += characters.charAt(randomIndex);
    }
    return password;
  }
}
