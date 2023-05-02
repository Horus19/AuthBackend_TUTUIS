import { AuthService } from './auth.service';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { RabbitMQService } from './rabbit-mq/rabbit-mq.service';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { ChangePasswordDto } from './dto/change-password.dto';

describe('AuthService', () => {
  let authService: AuthService;
  let userRepository: Repository<User>;
  let rabbitMQService: RabbitMQService;
  let jwtService: JwtService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
            verify: jest.fn(),
          },
        },
        RabbitMQService,
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    rabbitMQService = module.get<RabbitMQService>(RabbitMQService);
    jwtService = module.get<JwtService>(JwtService);
  });

  describe('blockUser', () => {
    it('should throw an UnauthorizedException if user is not found', async () => {
      const id = '1';
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      await expect(authService.blockUser(id)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(userRepository.findOne).toBeCalledWith({ where: { id } });
      expect(userRepository.save).not.toBeCalled();
    });

    it('should block user', async () => {
      const id = '1';
      const user = new User();
      user.id = id;
      user.isBlocked = false;
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
      jest.spyOn(userRepository, 'save').mockResolvedValue(user);

      const result = await authService.blockUser(id);
      expect(result).toEqual(user);
      expect(userRepository.findOne).toBeCalledWith({ where: { id } });
      expect(userRepository.save).toBeCalledWith({ ...user, isBlocked: true });
    });
  });

  describe('activateUser', () => {
    it('should activate user and return user with token', async () => {
      const token = 'valid_token';
      const user = new User();
      user.validationToken = token;
      jest.spyOn(authService, 'verifyToken').mockResolvedValue(true);
      jest.spyOn(authService, 'getJwtToken').mockReturnValue('jwt_token');
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
      jest.spyOn(userRepository, 'save').mockResolvedValue(user);

      const result = await authService.activateUser(token);

      expect(result).toEqual({
        ...user,
        token: 'jwt_token',
      });
      expect(user.isActivate).toBe(true);
      expect(user.validationToken).toBeNull();
      expect(userRepository.findOne).toBeCalledWith({
        where: { validationToken: token },
      });
      expect(userRepository.save).toBeCalledWith(user);
    });
  });

  describe('login', () => {
    it('should return a success response with user data and a token', async () => {
      // Arrange
      const email = 'test@example.com';
      const password = 'testPassword';
      const user = new User();
      user.id = '1';
      user.email = email;
      user.password = bcrypt.hashSync(password, 10);
      user.isActivate = true;
      user.fullName = 'John Doe';
      user.roles = ['user'];
      user.validationToken = 'testValidationToken';
      user.isBlocked = false;

      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
      jest.spyOn(authService, 'getJwtToken').mockReturnValue('testToken');

      // Act
      const result = await authService.login({ email, password });

      // Assert
      expect(result).toEqual({
        ok: true,
        id: '1',
        email,
        fullName: 'John Doe',
        isActivate: true,
        roles: ['user'],
        validationToken: 'testValidationToken',
        isBlocked: false,
        token: 'testToken',
      });
    });

    it('should return an invalid credentials error response', async () => {
      // Arrange
      const email = 'test@example.com';
      const password = 'testPassword';
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(undefined);

      // Act
      const result = await authService.login({ email, password });

      // Assert
      expect(result).toEqual({
        ok: false,
        message: 'Credenciales inválidas, usuario o contraseña incorrectos',
      });
    });

    it('should return an inactive account error response', async () => {
      // Arrange
      const email = 'test@example.com';
      const password = 'testPassword';
      const user = new User();
      user.id = '1';
      user.email = email;
      user.password = bcrypt.hashSync(password, 10);
      user.isActivate = false;
      user.fullName = 'John Doe';
      user.roles = ['user'];
      user.validationToken = 'testValidationToken';
      user.isBlocked = false;
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);

      // Act
      const result = await authService.login({ email, password });

      // Assert
      expect(result).toEqual({
        ok: false,
        message: `Su cuenta aún no está activada. Por favor, revise su correo electrónico y haga clic en el enlace de confirmación para activar su cuenta. Si no recibió el correo electrónico, revise su carpeta de spam o solicite uno nuevo desde la página de inicio de sesión.`,
      });
    });
  });

  describe('changePassword', () => {
    const id = '1';
    const password = 'password';
    const newPassword = 'newPassword';

    it('should change password successfully if password is correct', async () => {
      const changePasswordDto: ChangePasswordDto = {
        password,
        newPassword,
      };

      const user = new User();
      user.id = id;
      user.email = 'test@example.com';
      user.password = await bcrypt.hash(password, 10);

      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
      jest.spyOn(bcrypt, 'compareSync').mockReturnValue(true);
      await expect(
        authService.changePassword(id, changePasswordDto),
      ).resolves.toEqual(user);

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id },
        select: ['id', 'email', 'password'],
      });
    });

    it('should throw an UnauthorizedException if user is not found', async () => {
      const changePasswordDto: ChangePasswordDto = {
        password,
        newPassword,
      };

      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);

      await expect(
        authService.changePassword(id, changePasswordDto),
      ).rejects.toThrowError(
        new UnauthorizedException('Usuario no encontrado'),
      );

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id },
        select: ['id', 'email', 'password'],
      });
    });

    it('should throw an UnauthorizedException if password is incorrect', async () => {
      const changePasswordDto: ChangePasswordDto = {
        password: 'wrongPassword',
        newPassword,
      };

      const user = new User();
      user.id = id;
      user.email = 'test@example.com';
      user.password = await bcrypt.hash(password, 10);

      jest.spyOn(userRepository, 'findOne').mockResolvedValue(user);
      const spyCompareSync = jest
        .spyOn(bcrypt, 'compareSync')
        .mockReturnValue(false);

      await expect(
        authService.changePassword(id, changePasswordDto),
      ).rejects.toThrowError(
        new UnauthorizedException('Contraseña incorrecta'),
      );

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id },
        select: ['id', 'email', 'password'],
      });

      expect(spyCompareSync).toHaveBeenCalledWith(
        changePasswordDto.password,
        user.password,
      );
    });
  });
  describe('verifyToken', () => {
    it('should return false if token is invalid', async () => {
      const token = 'invalidToken';

      const result = await authService.verifyToken(token);

      expect(result).toBe(false);
    });
  });

  it('should create a valid auth token', async () => {
    const email = 'test@test.com';
    const expectedToken = 'valid.token.123';

    Object.defineProperty(jwtService, 'signAsync', {
      value: jest.fn().mockResolvedValue(expectedToken),
    });

    const result = await authService.createAuthToken(email);

    expect(result).toBe(expectedToken);
    expect(jwtService.signAsync).toHaveBeenCalledWith(
      { email },
      { expiresIn: '2h' },
    );
  });

  describe('checkAuthStatus', () => {
    it('should return an object with an ok property and a non-empty token', async () => {
      const user: User = new User();
      user.id = '1';
      user.email = 'test@test.com';
      user.fullName = 'John Doe';
      user.password = 'testPassword';

      // Mock the getJwtToken method
      const mockToken = 'mockToken';
      jest.spyOn(authService, 'getJwtToken').mockReturnValue(mockToken);

      const result = await authService.checkAuthStatus(user);

      expect(result).toHaveProperty('ok', true);
      expect(result.token).toBeTruthy();
      expect(typeof result.token).toBe('string');
      expect(result.token).toBe(mockToken);
    });
  });
});
