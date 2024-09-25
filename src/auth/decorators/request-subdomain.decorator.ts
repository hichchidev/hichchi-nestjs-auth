// noinspection JSUnusedGlobalSymbols

import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const Subdomain = createParamDecorator((_data: unknown, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest();
    return request["subdomain"];
});
