import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Reflector } from '@nestjs/core';
import { META_ROLES } from '../../decorators/role-protected.decorator';

@Injectable()
export class UserRoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const validRoles: string[] = this.reflector.get<string[]>(
      META_ROLES,
      context.getHandler(),
    );

    if (validRoles.length == 0) return true;

    const request = context.switchToHttp().getRequest();
    const { user } = request;

    if (!user) throw new Error('No user found');

    for (const role of user.roles) {
      if (validRoles.includes(role)) return true;
    }

    throw new ForbiddenException(
      '' +
        'EL usuario: ' +
        user.email +
        ' no tiene los permisos necesarios para acceder a este recurso. ' +
        'Los roles validos son: ' +
        validRoles.join(', '),
    );
  }
}
