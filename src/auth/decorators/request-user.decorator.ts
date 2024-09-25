import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { TokenUser } from "../types";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

export const CurrentUser = createParamDecorator((_data: unknown, ctx: ExecutionContext): TokenUser => {
    const request = ctx.switchToHttp().getRequest();
    const user: IUserEntity & TokenUser = request.user;
    delete user.password;
    delete user.salt;
    return user;
});
