import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ROLES_KEY } from "../decorators";
import { AuthErrors } from "../responses";
import { IUserEntity, IRoleEntity } from "hichchi-nestjs-common/interfaces";

@Injectable()
export class RoleGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles: string[] = this.reflector.getAllAndOverride<any[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!requiredRoles) {
            return true;
        }
        const { user } = context.switchToHttp().getRequest() as { user: IUserEntity };
        if (requiredRoles.some((role) => ((user.role as IRoleEntity).name || user.role) === role)) {
            return true;
        }
        throw new ForbiddenException(AuthErrors.AUTH_403_ROLE_FORBIDDEN);
    }
}
