import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { TokenUser } from "../types";

export const SocketId = createParamDecorator((_data: unknown, ctx: ExecutionContext): string | undefined => {
    const request = ctx.switchToHttp().getRequest();
    return (request.user as TokenUser)?.socketId;
});
