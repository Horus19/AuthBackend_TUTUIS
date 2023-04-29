import { Injectable } from '@nestjs/common';
import { connect, Channel } from 'amqplib';

@Injectable()
export class RabbitMQService {
  private channel: Channel;

  constructor() {
    this.connectToRabbitMQ();
  }

  async connectToRabbitMQ() {
    const connection = await connect('amqp://rabbitmq');
    this.channel = await connection.createChannel();
  }

  async sendMessage(queueName: string, message: string) {
    this.channel.assertQueue(queueName, {
      durable: true,
    });
    this.channel.sendToQueue(queueName, Buffer.from(message), {
      persistent: true,
    });
  }

  async receiveMessages(
    queueName: string,
    onMessageCallback: (message: any) => void,
  ) {
    this.channel.assertQueue(queueName, {
      durable: true,
    });
    this.channel.consume(
      queueName,
      (message) => {
        onMessageCallback(message.content.toString());
        this.channel.ack(message);
      },
      {
        noAck: false,
      },
    );
  }
}
