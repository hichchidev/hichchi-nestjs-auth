import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { TokenUser } from "../types/token-user.type";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

export const CurrentUser = createParamDecorator((_data: unknown, ctx: ExecutionContext): TokenUser | IUserEntity => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    delete user.password;
    delete user.salt;
    return user;
});
