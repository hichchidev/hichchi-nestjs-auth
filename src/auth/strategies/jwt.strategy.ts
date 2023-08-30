import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { IAuthOptions, ITokenData, IUserEntity, IUserService } from "../interfaces";
import { AuthErrors } from "../responses";
import { AUTH_OPTIONS, USER_SERVICE } from "../tokens";
import { cookieExtractor } from "../utils";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        @Inject(USER_SERVICE) private userService: IUserService,
        @Inject(AUTH_OPTIONS) authOptions: IAuthOptions,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
            ignoreExpiration: false,
            secretOrKey: authOptions.jwt.secret,
        });
    }

    // noinspection JSUnusedGlobalSymbols
    async validate(jwtPayload: ITokenData): Promise<IUserEntity> {
        try {
            const user = await this.userService.getUserById(jwtPayload.sub);
            if (!user) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN));
            }
            return user;
        } catch (err: any) {
            // LoggerService.error(err);
            return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN));
        }
    }
}
