import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { IUserEntity } from "../interfaces";

export const CurrentUser = createParamDecorator((_data: unknown, ctx: ExecutionContext): IUserEntity => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    delete user.password;
    delete user.salt;
    return user;
});
