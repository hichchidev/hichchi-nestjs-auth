// noinspection JSUnusedGlobalSymbols

import { AuthGuard } from "@nestjs/passport";
import { ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Observable } from "rxjs";
import { AuthErrors } from "../responses";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

@Injectable()
export class LocalAuthGuard extends AuthGuard("local") {
    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        return super.canActivate(context);
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handleRequest(err: any, user: IUserEntity, _info: any): any {
        // You can throw an exception based on either "info" or "err" arguments
        if (err || !user) {
            throw err || new UnauthorizedException(AuthErrors.AUTH_500_LOGIN);
        }
        delete user.password;
        delete user.salt;
        return user;
    }
}
