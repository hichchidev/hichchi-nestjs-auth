// noinspection JSUnusedGlobalSymbols,JSUnusedLocalSymbols

import { ExecutionContext, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { AuthErrors } from "../responses";
import { ExtractJwt } from "passport-jwt";
import { IAuthOptions, IUserEntity } from "../interfaces";
import { ACCESS_TOKEN_COOKIE_NAME, AUTH_OPTIONS, REFRESH_TOKEN_COOKIE_NAME } from "../tokens";
import { AuthService } from "../services/auth.service";
import { cookieExtractor } from "../utils";
import { RedisCacheService } from "hichchi-nestjs-common/cache";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
    constructor(
        @Inject(AUTH_OPTIONS) private readonly authOptions: IAuthOptions,
        private readonly authService: AuthService,
        private readonly cacheService: RedisCacheService,
    ) {
        super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const response = context.switchToHttp().getResponse();

        try {
            const accessToken = ExtractJwt.fromExtractors([cookieExtractor])(request);
            if (accessToken) {
                return this.activate(context);
            }

            const refreshToken = request.signedCookies[REFRESH_TOKEN_COOKIE_NAME];
            if (!refreshToken) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_NOT_LOGGED_IN));
            }

            const user = await this.authService.getUserByToken(refreshToken, true);
            const tokens = this.authService.generateTokens(user);
            await this.cacheService.setUser(user);

            request.signedCookies[ACCESS_TOKEN_COOKIE_NAME] = tokens.accessToken;

            response.cookie(ACCESS_TOKEN_COOKIE_NAME, tokens.refreshToken, {
                maxAge: Number(this.authOptions.jwt.expiresIn) * 1000,
                httpOnly: true,
                sameSite: this.authOptions.cookies.sameSite,
                secure: this.authOptions.cookies.secure,
                signed: true,
            });
            response.cookie(REFRESH_TOKEN_COOKIE_NAME, tokens.refreshToken, {
                maxAge: Number(this.authOptions.jwt.refreshExpiresIn) * 1000,
                httpOnly: true,
                sameSite: this.authOptions.cookies.sameSite,
                secure: this.authOptions.cookies.secure,
                signed: true,
            });

            return this.activate(context);
        } catch (err) {
            // LoggerService.error(err);
            response.clearCookie(ACCESS_TOKEN_COOKIE_NAME);
            response.clearCookie(REFRESH_TOKEN_COOKIE_NAME);
            return false;
        }
    }

    activate(context: ExecutionContext): Promise<boolean> {
        return super.canActivate(context) as Promise<boolean>;
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handleRequest(err: any, user: IUserEntity, _info: any): any {
        // You can throw an exception based on either "info" or "err" arguments
        if (err || !user) {
            throw err || new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN);
        }
        delete user.password;
        delete user.salt;
        return user;
    }
}
