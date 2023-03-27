import { createParamDecorator } from '@nestjs/common';

export const GetRawHeaders = createParamDecorator((data, ctx) => {
  const request = ctx.switchToHttp().getRequest();
  return request.rawHeaders;
});
