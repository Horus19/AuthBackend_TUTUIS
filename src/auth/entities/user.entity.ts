import { ApiProperty } from '@nestjs/swagger';
import {
  AfterInsert,
  BeforeInsert,
  BeforeUpdate,
  Column,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { ValidRoles } from '../interfaces/valid-roles';

@Entity({ name: 'users', synchronize: false })
export class User {
  @ApiProperty({
    example: 'c2fc71ee-e969-4083-8423-b363ec064326',
    description: 'identificador único del usuario',
    uniqueItems: true,
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    example: 'correo@correo.uis.edu.co',
    description: 'Correo del usuario',
    uniqueItems: true,
  })
  @Column('text', {
    unique: true,
  })
  email: string;

  @ApiProperty({
    example: '$2b$10$AnnvoIujasObgZR4oBC.8eB7T6Si9Pi3yz8zJzBrLRpRTZnQymkda',
    description: 'Contraseña del usuario',
  })
  @Column('text', {
    select: false,
  })
  password: string;

  @ApiProperty({
    example: 'Juan Perez',
    description: 'Nombre completo del usuario',
  })
  @Column('text')
  fullName: string;

  @ApiProperty({
    example: 'false',
    description:
      'Propiedad para definir si el usuario se encuentra autenticado',
  })
  @Column('bool', {
    default: false,
  })
  isActivate: boolean;

  @ApiProperty({ example: '[user]', description: 'Roles del usuario' })
  @Column('text', {
    array: true,
    default: [ValidRoles.ESTUDIANTE],
  })
  roles: string[];

  @ApiProperty({
    example: '123456',
    description: 'Token de validación del usuario',
  })
  @Column('text', {
    nullable: true,
  })
  validationToken: string;

  @ApiProperty({
    example: 'false',
    description: 'Propiedad para definir si el usuario se encuentra bloqueado',
  })
  @Column('bool', {
    default: false,
  })
  isBlocked: boolean;
  // @OneToMany(() => Product, (product) => product.user)
  // products: Product[];

  @BeforeInsert()
  emailToLowerCase() {
    this.email = this.email.toLowerCase().trim();
  }

  @BeforeUpdate()
  emailToLowerCaseUpdate() {
    this.emailToLowerCase();
  }

  @AfterInsert()
  logInsert() {
    console.log('Inserted User with id', this.id);
  }
}
