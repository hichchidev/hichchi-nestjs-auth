import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { TokenUser } from "../types";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

/**
 * Request User Decorator
 *
 * This decorator is used to get the current user from the request.CurrentUser
 *
 * @example
 * ```typescript
 * @Controller("user")
 * export class UserController {
 *     @Get()
 *     async getUsers(@CurrentUser() user: TokenUser): Promise<User[]> {
 *         // Implementation
 *     }
 * }
 * ```
 *
 * @returns {ParameterDecorator} The parameter decorator
 */
export function CurrentUser(): ParameterDecorator {
    return createParamDecorator((_data: unknown, ctx: ExecutionContext): TokenUser => {
        const request = ctx.switchToHttp().getRequest();
        const user: IUserEntity & TokenUser = request.user;
        delete user.password;
        delete user.salt;
        return user;
    })();
}
