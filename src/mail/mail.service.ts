import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';
import { BienvenidaDto } from './dto/bienvenida.dto';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendSimpleEmail(sendMailOptions: ISendMailOptions) {
    await this.mailerService.sendMail(sendMailOptions);
  }

  async sendWelcomeEmail(bienvenidaDto: BienvenidaDto) {
    try {
      await this.mailerService.sendMail({
        from: 'admin@tutuis.com',
        to: bienvenidaDto.email,
        subject: 'Bienvenid@ a Tutuis',
        template: 'Bienvenida',
        context: {
          nombre: bienvenidaDto.fullName,
          url_confirmacion: bienvenidaDto.url_confirmacion,
        },
      });
    } catch (e) {
      console.log(e);
      throw new InternalServerErrorException(e);
    }
  }
}
