import { AuthGuard } from "@nestjs/passport";
import {
    ExecutionContext,
    Inject,
    Injectable,
    InternalServerErrorException,
    UnauthorizedException,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { AuthErrors } from "../responses";
import { IGoogleProfile } from "../interfaces/google-profile.interface";
import { AUTH_OPTIONS } from "../tokens";
import { IAuthOptions } from "../interfaces";
import passport from "passport";
import { AuthStrategy } from "../enums/auth-strategies.enum";
import { Errors } from "hichchi-nestjs-common/responses";

@Injectable()
export class GoogleAuthGuard extends AuthGuard(AuthStrategy.GOOGLE) {
    constructor(@Inject(AUTH_OPTIONS) readonly authOptions: IAuthOptions) {
        super();
    }

    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        if (
            !this.authOptions.googleAuth.clientId ||
            !this.authOptions.googleAuth.clientSecret ||
            !this.authOptions.googleAuth.callbackUrl
        ) {
            throw new InternalServerErrorException(Errors.E_404_NOT_IMPLEMENTED);
        }

        const request = context.switchToHttp().getRequest();
        const response = context.switchToHttp().getResponse();
        const { redirectUrl } = request.query;

        const googleOptions = {
            session: false,
            state: JSON.stringify({ redirectUrl }),
        };

        return new Promise((resolve, reject) => {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            passport.authenticate(AuthStrategy.GOOGLE, googleOptions, (err: any, user: IGoogleProfile, _info: any) => {
                if (err || !user) {
                    reject(new UnauthorizedException(AuthErrors.AUTH_500_SOCIAL_LOGIN));
                } else {
                    request.user = user;
                    resolve(true);
                }
            })(request, response);
        });
    }
}
