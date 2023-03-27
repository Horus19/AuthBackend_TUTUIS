import { Injectable, InternalServerErrorException, Logger, UnauthorizedException } from "@nestjs/common";
import { CreateUserDto, LoginUserDto } from "./dto";
import { User } from "./entities/user.entity";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";

import * as bcrypt from "bcrypt";
import { JwtPayload } from "./interfaces/jwt-payload.interface";
import { JwtService } from "@nestjs/jwt";


@Injectable()
export class AuthService {

  private readonly logger = new Logger('AuthService');

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService
  ) {
  }

  async create(createAuthDto: CreateUserDto) {
    try {
      const { password, ...userData } = createAuthDto;
      const user = this.userRepository.create({
        ...userData,
        password: bcrypt.hashSync(password, 10)
      });
      await this.userRepository.save(user);
      delete user.password;
      return {
        ...user,
        token: this.getJwtToken({ id: user.id })
      };

      //TODO: Retornar el JWT de acceso
    } catch (e) {
      this.handleError(e);
    }
    return 'This action adds a new auth';
  }

  private getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  private handleError(error: Error) : never {
    this.logger.error(error.message, error.stack);
    throw new InternalServerErrorException('Internal Server Error ', error.message);
  }

  async login(loginUserDto: LoginUserDto) {

    const { email, password } = loginUserDto;
    const user = await this.userRepository.findOne({
      where: { email },
      select: { email : true, password : true, id: true }
    });

    if(!user) {
      throw new UnauthorizedException('Invalid credentials, user not found');
    }

    if(!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Invalid credentials, password is incorrect');
    }

    delete user.password;

    return {
      ...user,
      token: this.getJwtToken({ id: user.id })
    };
  }

  async checkAuthStatus(user: User) {
    return {
      ...user,
      token: this.getJwtToken({ id: user.id })
    };
  }
}
