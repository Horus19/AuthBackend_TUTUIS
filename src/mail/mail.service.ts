import { Injectable, NotFoundException } from "@nestjs/common";
import { ISendMailOptions, MailerService } from "@nestjs-modules/mailer";

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendSimpleEmail(sendMailOptions: ISendMailOptions) {
    await this.mailerService.sendMail(sendMailOptions);
  }

  async sendWelcomeEmail() {
    try {
      await this.mailerService.sendMail({
        from: 'admin@tutuis.com',
        to: 'camacho19992012@gmail.com',
        subject: 'Welcome to Tutuis 2',
        template: 'Bienvenida',
        context: {
          'nombre': 'Horacio',
          'url_confirmacion': 'http://google.com',
          'sitio_web': 'http://tutuis.com',
        }
      });
    } catch (e) {
      console.log(e);
      throw new NotFoundException;
    }
  }
}
