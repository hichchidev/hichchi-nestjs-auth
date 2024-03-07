import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { IAuthOptions, IJwtPayload } from "../interfaces";
import { AuthErrors } from "../responses";
import { AUTH_OPTIONS } from "../tokens";
import { cookieExtractor } from "../extractors";
import { AuthMethod } from "../enums/auth-type.enum";
import { AuthService } from "../services/auth.service";
import { LoggerService } from "hichchi-nestjs-common/services";
import { TokenUser } from "../types/token-user.type";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        @Inject(AUTH_OPTIONS) readonly authOptions: IAuthOptions,
        private readonly authService: AuthService,
    ) {
        super({
            jwtFromRequest:
                authOptions.authMethod === AuthMethod.COOKIE
                    ? ExtractJwt.fromExtractors([cookieExtractor])
                    : ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: authOptions.jwt.secret,
            passReqToCallback: true,
        });
    }

    // noinspection JSUnusedGlobalSymbols
    async validate(request: Request, jwtPayload: IJwtPayload): Promise<TokenUser> {
        try {
            const accessToken: string = request.headers["authorization"].split(" ")[1];
            const logout = Boolean(request.url.match("/logout"));
            return await this.authService.validateUserUsingJWT(jwtPayload, accessToken, logout);
        } catch (err: any) {
            LoggerService.error(err);
            return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN));
        }
    }
}
