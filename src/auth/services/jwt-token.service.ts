import { Inject, Injectable } from "@nestjs/common";
import { IAuthOptions, IJwtPayload } from "../interfaces";
import { JwtService } from "@nestjs/jwt";
import { AUTH_OPTIONS } from "../tokens";

@Injectable()
export class JwtTokenService {
    constructor(
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        private readonly jwtService: JwtService,
    ) {}

    createToken(payload: IJwtPayload): string {
        return this.jwtService.sign(payload, {
            secret: this.authOptions.jwt.secret,
            expiresIn: this.authOptions.jwt.expiresIn,
        });
    }

    createRefreshToken(payload: IJwtPayload): string {
        return this.jwtService.sign(payload, {
            secret: this.authOptions.jwt.refreshSecret,
            expiresIn: this.authOptions.jwt.refreshExpiresIn,
        });
    }

    verifyAccessToken(accessToken: string): IJwtPayload {
        return this.jwtService.verify(accessToken, {
            secret: this.authOptions.jwt.secret,
        });
    }

    verifyRefreshToken(refreshToken: string): IJwtPayload {
        return this.jwtService.verify(refreshToken, {
            secret: this.authOptions.jwt.refreshSecret,
        });
    }
}
