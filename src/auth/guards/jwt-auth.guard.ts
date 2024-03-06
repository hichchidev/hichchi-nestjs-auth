// noinspection JSUnusedGlobalSymbols,JSUnusedLocalSymbols

import { ExecutionContext, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { AuthErrors } from "../responses";
import { ExtractJwt } from "passport-jwt";
import { IAuthOptions, ICacheUser } from "../interfaces";
import { ACCESS_TOKEN_COOKIE_NAME, AUTH_OPTIONS, REFRESH_TOKEN_COOKIE_NAME } from "../tokens";
import { AuthService } from "../services/auth.service";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { cookieExtractor } from "../extractors";
import { LoggerService } from "hichchi-nestjs-common/services";
import { AuthType } from "../enums/auth-type.enum";
import { UserCacheService } from "../services/user-cache.service";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
    constructor(
        @Inject(AUTH_OPTIONS) private readonly authOptions: IAuthOptions,
        private readonly authService: AuthService,
        private readonly cacheService: UserCacheService,
    ) {
        super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const response = context.switchToHttp().getResponse();

        try {
            const accessToken =
                this.authOptions.authType === AuthType.COOKIE
                    ? ExtractJwt.fromExtractors([cookieExtractor])(request)
                    : ExtractJwt.fromAuthHeaderAsBearerToken()(request);

            if (accessToken) {
                return this.activate(context);
            }

            if (this.authOptions.authType === AuthType.COOKIE) {
                const refreshToken = request.signedCookies[REFRESH_TOKEN_COOKIE_NAME];
                if (!refreshToken) {
                    return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_NOT_LOGGED_IN));
                }

                const user = await this.authService.getUserByToken(refreshToken, true);
                const tokens = this.authService.generateTokens(user);

                const cacheUser: ICacheUser = (await this.cacheService.getUser(user.id)) ?? { ...user, sessions: [] };

                cacheUser.sessions = cacheUser.sessions.filter((session) => session.refreshToken !== refreshToken);
                cacheUser.sessions.push({ accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });

                await this.cacheService.setUser(cacheUser);

                request.signedCookies[ACCESS_TOKEN_COOKIE_NAME] = tokens.accessToken;

                response.cookie(ACCESS_TOKEN_COOKIE_NAME, tokens.refreshToken, {
                    maxAge: Number(this.authOptions.jwt.expiresIn) * 1000,
                    httpOnly: false,
                    sameSite: this.authOptions.cookies.sameSite,
                    secure: this.authOptions.cookies.secure,
                    signed: true,
                });
                response.cookie(REFRESH_TOKEN_COOKIE_NAME, tokens.refreshToken, {
                    maxAge: Number(this.authOptions.jwt.refreshExpiresIn) * 1000,
                    httpOnly: false,
                    sameSite: this.authOptions.cookies.sameSite,
                    secure: this.authOptions.cookies.secure,
                    signed: true,
                });

                return this.activate(context);
            }

            return false;
        } catch (err) {
            LoggerService.error(err);
            if (this.authOptions.authType === AuthType.COOKIE) {
                response.clearCookie(ACCESS_TOKEN_COOKIE_NAME);
                response.clearCookie(REFRESH_TOKEN_COOKIE_NAME);
            }
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
