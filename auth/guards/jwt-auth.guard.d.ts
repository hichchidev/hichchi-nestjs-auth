import { ExecutionContext } from "@nestjs/common";
import { IAuthOptions } from "../interfaces";
import { AuthService } from "../services/auth.service";
import { RedisCacheService } from "hichchi-nestjs-common/cache";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
declare const JwtAuthGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class JwtAuthGuard extends JwtAuthGuard_base {
    private readonly authOptions;
    private readonly authService;
    private readonly cacheService;
    constructor(authOptions: IAuthOptions, authService: AuthService, cacheService: RedisCacheService);
    canActivate(context: ExecutionContext): Promise<boolean>;
    activate(context: ExecutionContext): Promise<boolean>;
    handleRequest(err: any, user: IUserEntity, _info: any): any;
}
export {};
//# sourceMappingURL=jwt-auth.guard.d.ts.map