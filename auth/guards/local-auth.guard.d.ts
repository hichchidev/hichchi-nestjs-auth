import { ExecutionContext } from "@nestjs/common";
import { Observable } from "rxjs";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
declare const LocalAuthGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class LocalAuthGuard extends LocalAuthGuard_base {
    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean>;
    handleRequest(err: any, user: IUserEntity, _info: any): any;
}
export {};
//# sourceMappingURL=local-auth.guard.d.ts.map