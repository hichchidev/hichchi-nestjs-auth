import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { IAuthOptions, IJwtPayload } from "../interfaces";
import { AuthErrors } from "../responses";
import { AUTH_OPTIONS } from "../tokens";
import { cookieExtractor } from "../extractors";
import { AuthMethod } from "../enums";
import { AuthService } from "../services";
import { LoggerService } from "hichchi-nestjs-common/services";
import { TokenUser } from "../types";

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
            let socketId: string;
            if (this.authOptions.socket?.idKey) {
                socketId = request.headers[this.authOptions.socket.idKey.replace("-", "").toLowerCase()];
            }
            const logout = Boolean(request.url.match("/logout"));
            const user = await this.authService.validateUserUsingJWT(jwtPayload, accessToken, logout);
            user.socketId = socketId;
            return user;
        } catch (err: any) {
            LoggerService.error(err);
            return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN));
        }
    }
}
