import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { PERMISSION_KEY } from "../decorators";
import { AuthErrors } from "../responses";
import { IUserEntity, IRoleEntity } from "hichchi-nestjs-common/interfaces";

@Injectable()
export class PermissionGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const requiredPermission: string = this.reflector.getAllAndOverride<string>(PERMISSION_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!requiredPermission) {
            return true;
        }
        const { user } = context.switchToHttp().getRequest() as { user: IUserEntity };
        if ((user.role as IRoleEntity).permissions?.includes(requiredPermission)) {
            return true;
        }
        throw new ForbiddenException(AuthErrors.AUTH_403_ROLE_FORBIDDEN);
    }
}
