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

    /**
     * Create a new JWT token
     * @param {IJwtPayload} payload Payload to be signed
     * @returns {string} JWT access token
     */
    createToken(payload: IJwtPayload): string {
        return this.jwtService.sign(payload, {
            secret: this.authOptions.jwt.secret,
            expiresIn: this.authOptions.jwt.expiresIn,
        });
    }

    /**
     * Create a new refresh token
     * @param {IJwtPayload} payload Payload to be signed
     * @returns {string} JWT refresh token
     */
    createRefreshToken(payload: IJwtPayload): string {
        return this.jwtService.sign(payload, {
            secret: this.authOptions.jwt.refreshSecret,
            expiresIn: this.authOptions.jwt.refreshExpiresIn,
        });
    }

    /**
     * Verify the access token
     * @param {string} accessToken Access token to be verified
     * @returns {IJwtPayload} Verified payload
     */
    verifyAccessToken(accessToken: string): IJwtPayload {
        return this.jwtService.verify(accessToken, {
            secret: this.authOptions.jwt.secret,
        });
    }

    /**
     * Verify the refresh token
     * @param {string} refreshToken Refresh token to be verified
     * @returns {IJwtPayload} Verified payload
     */
    verifyRefreshToken(refreshToken: string): IJwtPayload {
        return this.jwtService.verify(refreshToken, {
            secret: this.authOptions.jwt.refreshSecret,
        });
    }
}
