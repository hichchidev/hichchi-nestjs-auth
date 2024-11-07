// noinspection JSUnusedGlobalSymbols,ExceptionCaughtLocallyJS

import {
    BadRequestException,
    HttpException,
    Inject,
    Injectable,
    InternalServerErrorException,
    NotFoundException,
    UnauthorizedException,
} from "@nestjs/common";
import {
    IAuthOptions,
    IAuthResponse,
    ICacheUser,
    IJwtPayload,
    IRegisterDto,
    ITokenResponse,
    IUserService,
} from "../interfaces";
import { ACCESS_TOKEN_COOKIE_NAME, AUTH_OPTIONS, REFRESH_TOKEN_COOKIE_NAME, USER_SERVICE } from "../tokens";
import { pbkdf2Sync, randomBytes, randomInt } from "crypto";
import { JsonWebTokenError, TokenExpiredError } from "@nestjs/jwt";
import { AuthErrors } from "../responses";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import {
    EmailVerifyDto,
    RequestResetDto,
    ResendEmailVerifyDto,
    ResetPasswordDto,
    ResetPasswordTokenVerifyDto,
    UpdatePasswordDto,
} from "../dtos";
import { AuthField, AuthMethod } from "../enums";
import { Request, Response } from "express";
import { UserCacheService } from "./user-cache.service";
import { JwtTokenService } from "./jwt-token.service";
import { LoggerService } from "hichchi-nestjs-common/services";
import { Errors, SuccessResponse } from "hichchi-nestjs-common/responses";
import { v4 as uuid } from "uuid";
import { TokenVerifyService } from "./token-verify.service";
import { TokenUser } from "../types";
import { generateTokenUser } from "../utils";

@Injectable()
export class AuthService {
    constructor(
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        @Inject(USER_SERVICE) private userService: IUserService,
        private readonly jwtTokenService: JwtTokenService,
        private readonly cacheService: UserCacheService,
        private readonly tokenVerifyService: TokenVerifyService,
    ) {}

    /**
     * Generate a random hash
     * @returns {string} Random hash
     */
    public static generateRandomHash(length: number = 48): string {
        return randomBytes(length).toString("hex");
    }

    /**
     * Generate a random secure password
     * @param {number} length Length of the password
     * @returns {string} Random password
     */
    public static generateRandomPassword(length: number): string {
        const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lowercase = "abcdefghijklmnopqrstuvwxyz";
        const numbers = "0123456789";
        const symbols = "!@#$%&*";

        const allCharacters = uppercase + lowercase + numbers + symbols;

        const getRandomSecureIndex = (max: number): number => {
            return randomInt(0, max);
        };

        let password = "";
        password += uppercase[getRandomSecureIndex(uppercase.length)];
        password += lowercase[getRandomSecureIndex(lowercase.length)];
        password += numbers[getRandomSecureIndex(numbers.length)];
        password += symbols[getRandomSecureIndex(symbols.length)];

        for (let i = password.length; i < length; i++) {
            password += allCharacters[getRandomSecureIndex(allCharacters.length)];
        }

        password = password
            .split("")
            .sort(() => 0.5 - Math.random())
            .join("");

        return password;
    }

    /**
     * Generate a password hash and salt
     * @param {string} password Password to hash
     * @returns {{salt: string, password: string}} Hashed password and salt
     */
    public static generatePassword(password: string): { salt: string; password: string } {
        const salt = randomBytes(32).toString("hex");
        const hash = pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
        return { salt, password: hash };
    }

    /**
     * Verify password with hash and salt
     *
     * @param {string} password Password to verify
     * @param {string} hash Hashed password
     * @param {string} salt Salt
     * @returns {boolean} Verification status
     */
    public static verifyHash(password: string, hash: string, salt: string): boolean {
        const generatedHash = pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
        return hash === generatedHash;
    }

    /**
     * Authenticate a user
     * @param {string} username Username or email
     * @param {string} password Password
     * @param {string} socketId Socket ID
     * @param {string} subdomain Subdomain
     * @returns {Promise<IUserEntity>} Authenticated user
     */
    async authenticate(username: string, password: string, socketId?: string, subdomain?: string): Promise<TokenUser> {
        const INVALID_CREDS =
            this.authOptions.authField === AuthField.EMAIL
                ? AuthErrors.AUTH_401_INVALID_EMAIL_PASSWORD
                : AuthErrors.AUTH_401_INVALID_UNAME_PASSWORD;

        try {
            const user =
                this.authOptions.authField === AuthField.USERNAME
                    ? await this.userService.getUserByUsername?.(username, subdomain)
                    : this.authOptions.authField === AuthField.EMAIL
                      ? await this.userService.getUserByEmail?.(username, subdomain)
                      : await this.userService.getUserByUsernameOrEmail?.(username, subdomain);

            if (!user) {
                return Promise.reject(new UnauthorizedException(INVALID_CREDS));
            }
            if (!AuthService.verifyHash(password, user.password, user.salt)) {
                return Promise.reject(new UnauthorizedException(INVALID_CREDS));
            }
            if (this.authOptions.checkEmailVerified && !user.emailVerified) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_EMAIL_NOT_VERIFIED));
            }
            // if (user.status === Status.PENDING) {
            //     return Promise.reject(new ForbiddenException(AuthErrors.AUTH_403_PENDING));
            // }
            // if (user.status !== Status.ACTIVE) {
            //     return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_NOT_ACTIVE));
            // }

            const tokenResponse = this.generateTokens(user);

            const cacheUser = await this.updateCacheUser(user, tokenResponse);

            return generateTokenUser(cacheUser, tokenResponse.accessToken, socketId);
        } catch (err) {
            LoggerService.error(err);
            throw new UnauthorizedException(INVALID_CREDS);
        }
    }

    /**
     * Authenticate a user using JWT
     * @param {IJwtPayload} payload JWT payload
     * @param {string} accessToken Access token
     * @param {boolean} logout Logout status
     * @param {string} socketId Socket ID
     * @returns {Promise<TokenUser>} Token user
     */
    async authenticateJWT(
        payload: IJwtPayload,
        accessToken: string,
        logout: boolean,
        socketId?: string,
    ): Promise<TokenUser> {
        try {
            this.jwtTokenService.verifyAccessToken(accessToken);
        } catch (err) {
            if (err instanceof TokenExpiredError) {
                if (logout) {
                    return { id: payload.sub } as TokenUser;
                }
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_EXPIRED_TOKEN));
            } else if (err instanceof JsonWebTokenError) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN));
            }
            throw err;
        }

        const cacheUser = await this.cacheService.getUser(payload.sub);

        if (
            !cacheUser ||
            !cacheUser.sessions?.length ||
            !cacheUser.sessions?.find((session) => session.accessToken === accessToken)
        ) {
            return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN));
        }

        return generateTokenUser(cacheUser, accessToken, socketId);
    }

    /**
     * Ger a user by token
     * @param {string} token Token
     * @param {boolean} refresh Weather if the token is a refresh token
     * @returns {Promise<IUserEntity>} User entity
     */
    public async getUserByToken(token: string, refresh?: boolean): Promise<IUserEntity> {
        try {
            const payload = refresh
                ? this.jwtTokenService.verifyRefreshToken(token)
                : this.jwtTokenService.verifyAccessToken(token);
            const user = await this.userService.getUserById(payload.sub);
            if (!user) {
                return null;
            }
            return user;
        } catch (err) {
            LoggerService.error(err);
            return null;
        }
    }

    /**
     * Generate access and refresh tokens
     * @param {IUserEntity} user User entity
     * @returns {ITokenResponse} Token response
     */
    generateTokens(user: IUserEntity): ITokenResponse {
        const payload: IJwtPayload = {
            sub: user.id,
            username: user.username,
            email: user.email,
        };

        const accessToken: string = this.jwtTokenService.createToken(payload);

        const refreshToken: string = this.jwtTokenService.createRefreshToken(payload);

        return {
            accessToken,
            refreshToken,
            accessTokenExpiresIn: `${this.authOptions.jwt.expiresIn}s`,
            refreshTokenExpiresIn: `${this.authOptions.jwt.refreshExpiresIn}s`,
        };
    }

    /**
     * Update the cache user
     * @param user User entity
     * @param tokenResponse Token response
     * @param oldRefreshToken Old refresh token
     */
    async updateCacheUser(
        user: IUserEntity,
        tokenResponse: ITokenResponse,
        oldRefreshToken?: string,
    ): Promise<ICacheUser> {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { password, salt, ...rest } = new this.authOptions.viewDto().formatDataSet(user);
        const cacheUser: ICacheUser = { ...rest, sessions: (await this.cacheService.getUser(user.id))?.sessions ?? [] };

        if (cacheUser.sessions.length) {
            if (oldRefreshToken) {
                cacheUser.sessions = cacheUser.sessions.filter((session) => session.refreshToken !== oldRefreshToken);
            }
            cacheUser.sessions.push({
                sessionId: uuid(),
                accessToken: tokenResponse.accessToken,
                refreshToken: tokenResponse.refreshToken,
            });
        } else {
            cacheUser.sessions = [
                { sessionId: uuid(), accessToken: tokenResponse.accessToken, refreshToken: tokenResponse.refreshToken },
            ];
        }

        await this.cacheService.setUser(cacheUser);

        return cacheUser;
    }

    /**
     * Set the auth cookies
     * @param response Response object
     * @param tokenResponse Token response
     */
    setAuthCookies(response: Response, tokenResponse: ITokenResponse): void {
        if (this.authOptions.authMethod === AuthMethod.COOKIE) {
            response.cookie(ACCESS_TOKEN_COOKIE_NAME, tokenResponse.accessToken, {
                maxAge: this.authOptions.jwt.expiresIn * 1000,
                httpOnly: true,
                sameSite: this.authOptions.cookies.sameSite,
                secure: this.authOptions.cookies.secure,
                signed: true,
            });
            response.cookie(REFRESH_TOKEN_COOKIE_NAME, tokenResponse.refreshToken, {
                maxAge: this.authOptions.jwt.refreshExpiresIn * 1000,
                httpOnly: true,
                sameSite: this.authOptions.cookies.sameSite,
                secure: this.authOptions.cookies.secure,
                signed: true,
            });
        }
    }

    /**
     * Register a new user
     * @param {Request} request Request object
     * @param {IRegisterDto} registerDto Register DTO
     * @returns {Promise<IUserEntity>} Registered user
     */
    async register(request: Request, registerDto: IRegisterDto): Promise<IUserEntity> {
        const { password: rawPass, ...rest } = registerDto;
        const { password, salt } = AuthService.generatePassword(rawPass);
        const user = await this.userService.registerUser({ ...rest, password, salt });
        await this.sendVerificationEmail(user);
        delete user.password;
        delete user.salt;
        this.userService.onRegister?.(request, user.id).catch();
        return user;
    }

    /**
     * Login a user
     * @param {Request} request Request object
     * @param {TokenUser} tokenUser Token user
     * @param {Response} response Response object
     * @returns {Promise<IAuthResponse>} Auth response
     */
    async login(request: Request, tokenUser: TokenUser, response: Response): Promise<IAuthResponse> {
        try {
            const { sessionId, accessToken, refreshToken, ...user } = tokenUser;

            const tokenResponse: ITokenResponse = {
                accessToken: accessToken,
                refreshToken: refreshToken,
                accessTokenExpiresIn: `${this.authOptions.jwt.expiresIn}s`,
                refreshTokenExpiresIn: `${this.authOptions.jwt.refreshExpiresIn}s`,
            };

            this.setAuthCookies(response, tokenResponse);

            this.userService.onLogin?.(request, tokenUser as TokenUser).catch();

            return {
                ...tokenResponse,
                sessionId,
                user,
            };
        } catch (err) {
            this.userService.onLogin?.(request, tokenUser, err as Error).catch();
            throw err;
        }
    }

    /**
     * Get the current user
     * @param {Request} request Request object
     * @param {TokenUser} tokenUser Token user
     */
    async getCurrentUser(request: Request, tokenUser: TokenUser): Promise<IUserEntity | undefined> {
        try {
            const user = await this.userService.getUserById(tokenUser.id);
            this.userService.onGetCurrentUser?.(request, tokenUser).catch();
            return user;
        } catch (err) {
            this.userService.onGetCurrentUser?.(request, tokenUser, err as Error).catch();
            throw err;
        }
    }

    /**
     * Refresh the tokens
     * @param {Request} request Request object
     * @param token Refresh token
     * @param response Response object
     * @returns {Promise<ITokenResponse>} Token response
     */
    async refreshTokens(request: Request, token: string, response: Response): Promise<ITokenResponse> {
        try {
            const { sub } = this.jwtTokenService.verifyRefreshToken(token);

            const user = await this.userService.getUserById(sub);
            if (!user) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_REFRESH_TOKEN));
            }

            const tokenResponse: ITokenResponse = this.generateTokens(user);

            const cacheUser = await this.updateCacheUser(user, tokenResponse, token);
            const tokenUser = generateTokenUser(cacheUser, tokenResponse.accessToken);
            this.setAuthCookies(response, tokenResponse);

            this.userService.onRefreshTokens?.(request, tokenUser).catch();

            return tokenResponse;
        } catch (err) {
            if (err instanceof TokenExpiredError) {
                throw new UnauthorizedException(AuthErrors.AUTH_401_EXPIRED_REFRESH_TOKEN);
            } else if (err instanceof JsonWebTokenError) {
                throw new UnauthorizedException(AuthErrors.AUTH_401_INVALID_REFRESH_TOKEN);
            }
        }
    }

    /**
     * Change user password
     * @param {Request} request Request object
     * @param {TokenUser} tokenUser Token user
     * @param {UpdatePasswordDto} updatePasswordDto Update password DTO
     * @returns {Promise<IUserEntity>} Updated user
     */
    async changePassword(
        request: Request,
        tokenUser: TokenUser,
        updatePasswordDto: UpdatePasswordDto,
    ): Promise<IUserEntity> {
        try {
            const { password, salt } = await this.userService.getUserById(tokenUser.id);
            const { oldPassword, newPassword } = updatePasswordDto;
            if (AuthService.verifyHash(oldPassword, password, salt)) {
                const { password, salt } = AuthService.generatePassword(newPassword);
                const user = await this.userService.updateUserById(tokenUser.id, { password, salt }, {
                    id: tokenUser.id,
                } as IUserEntity);
                delete user.password;
                delete user.salt;
                this.userService.onChangePassword?.(request, tokenUser).catch();
                return user;
            }
            throw new NotFoundException(AuthErrors.AUTH_401_INVALID_PASSWORD);
        } catch (err) {
            this.userService.onChangePassword?.(request, tokenUser, err as Error).catch();
            throw err;
        }
    }

    /**
     * Send a verification email
     * @param {IUserEntity} user User entity
     */
    async sendVerificationEmail(user: IUserEntity): Promise<void> {
        if (!this.userService.sendVerificationEmail) {
            throw new NotFoundException(Errors.E_404_NOT_IMPLEMENTED);
        }

        try {
            const token = AuthService.generateRandomHash(16);
            await this.tokenVerifyService.saveEmailVerifyToken(user.id, token);
            await this.userService.sendVerificationEmail(user.id, token);
        } catch (err) {
            if (err instanceof HttpException) {
                throw err;
            }
            throw new InternalServerErrorException(AuthErrors.AUTH_500_SEND_EMAIL_VERIFICATION);
        }
    }

    /**
     * Resend a verification email
     * @param {Request} request Request object
     * @param {ResendEmailVerifyDto} resendEmailVerifyDto Resend email verify DTO
     * @returns {Promise<SuccessResponse>} Success response
     */
    async resendEmailVerification(
        request: Request,
        resendEmailVerifyDto: ResendEmailVerifyDto,
    ): Promise<SuccessResponse> {
        if (!this.userService.sendVerificationEmail) {
            throw new NotFoundException(Errors.E_404_NOT_IMPLEMENTED);
        }

        const user = await this.userService.getUserByEmail(resendEmailVerifyDto.email);
        if (user) {
            if (user.emailVerified) {
                throw new BadRequestException(AuthErrors.AUTH_400_EMAIL_ALREADY_VERIFIED);
            }
            await this.sendVerificationEmail(user);
            this.userService.onResendVerificationEmail?.(request, user.id).catch();
            return new SuccessResponse("Verification email sent successfully");
        }

        throw new NotFoundException(AuthErrors.AUTH_404_EMAIL);
    }

    /**
     * Verify an account
     * @param {Request} request Request object
     * @param {EmailVerifyDto} emailVerifyDto Email verify DTO
     */
    async verifyEmail(request: Request, emailVerifyDto: EmailVerifyDto): Promise<boolean> {
        if (!this.userService.sendVerificationEmail) {
            throw new NotFoundException(Errors.E_404_NOT_IMPLEMENTED);
        }

        try {
            const userId = await this.tokenVerifyService.getUserIdByEmailVerifyToken(emailVerifyDto.token);
            if (userId) {
                await this.userService.updateUserById(userId, { emailVerified: true }, { id: userId } as IUserEntity);
                await this.tokenVerifyService.clearEmailVerifyTokenByUserId(userId);
                this.userService.onVerifyEmail?.(request, userId, true).catch();
                return true;
            }
            this.userService.onVerifyEmail?.(request, userId, false).catch();
            return false;
        } catch {
            return false;
        }
    }

    /**
     * Request password reset email
     * @param {Request} request Request object
     * @param {RequestResetDto} requestResetDto Request reset DTO
     * @returns {Promise<SuccessResponse>} Success response
     */
    async requestPasswordReset(request: Request, requestResetDto: RequestResetDto): Promise<SuccessResponse> {
        if (!this.userService.getUserByEmail || !this.userService.sendPasswordResetEmail) {
            throw new NotFoundException(Errors.E_404_NOT_IMPLEMENTED);
        }

        try {
            const user = await this.userService.getUserByEmail?.(requestResetDto.email);
            if (user) {
                const token = AuthService.generateRandomHash(16);
                const setToken = await this.tokenVerifyService.savePasswordResetToken(user.id, token);
                const emailSent = await this.userService.sendPasswordResetEmail(user.email, token);

                if (setToken && emailSent) {
                    this.userService.onRequestPasswordReset?.(request, user.id).catch();
                    return new SuccessResponse("Password reset email sent successfully");
                }

                return Promise.reject(new InternalServerErrorException(AuthErrors.AUTH_500_REQUEST_PASSWORD_RESET));
            }
        } catch (err) {
            if (err instanceof HttpException) {
                throw err;
            }
            throw new InternalServerErrorException(AuthErrors.AUTH_500_REQUEST_PASSWORD_RESET);
        }
    }

    /**
     * Verify a password reset token
     * @param {Request} request Request object
     * @param {ResetPasswordTokenVerifyDto} verifyDto Reset password token verify DTO
     * @returns {Promise<SuccessResponse>} Success response
     */
    async verifyResetPasswordToken(request: Request, verifyDto: ResetPasswordTokenVerifyDto): Promise<SuccessResponse> {
        if (!this.userService.getUserByEmail || !this.userService.sendPasswordResetEmail) {
            throw new NotFoundException(Errors.E_404_NOT_IMPLEMENTED);
        }

        const userId = await this.tokenVerifyService.getUserIdByPasswordResetToken(verifyDto.token);
        if (userId) {
            this.userService.onVerifyResetPasswordToken?.(request, userId).catch();
            return new SuccessResponse("Valid password reset token");
        }

        throw new NotFoundException(AuthErrors.AUTH_401_EXPIRED_OR_INVALID_PASSWORD_RESET_TOKEN);
    }

    /**
     * Reset a user password
     * @param {Request} request Request object
     * @param {ResetPasswordDto} resetPasswordDto Reset password DTO
     * @returns {Promise<SuccessResponse>} Success response
     */
    async resetPassword(request: Request, resetPasswordDto: ResetPasswordDto): Promise<SuccessResponse> {
        if (!this.userService.getUserByEmail || !this.userService.sendPasswordResetEmail) {
            throw new NotFoundException(Errors.E_404_NOT_IMPLEMENTED);
        }

        try {
            const { token, password } = resetPasswordDto;
            const userId = await this.tokenVerifyService.getUserIdByPasswordResetToken(token);
            if (!userId) {
                return Promise.reject(
                    new NotFoundException(AuthErrors.AUTH_401_EXPIRED_OR_INVALID_PASSWORD_RESET_TOKEN),
                );
            }

            const { password: passwordHash, salt } = AuthService.generatePassword(password);
            const user = await this.userService.updateUserById(userId, { password: passwordHash, salt }, {
                id: userId,
            } as IUserEntity);
            if (!user) {
                return Promise.reject(new NotFoundException(AuthErrors.AUTH_500_PASSWORD_RESET));
            }

            await this.tokenVerifyService.clearPasswordResetTokenByUserId(userId);

            this.userService.onResetPassword?.(request, userId).catch();

            return new SuccessResponse("Password reset successfully");
        } catch {
            return Promise.reject(new NotFoundException(AuthErrors.AUTH_500_PASSWORD_RESET));
        }
    }

    /**
     * Logout a user
     * @param {Request} request Request object
     * @param {TokenUser} tokenUser Token user
     * @param {Response} response Response object
     * @returns {Promise<SuccessResponse>} Success response
     */
    async logout(request: Request, tokenUser: TokenUser, response: Response): Promise<SuccessResponse> {
        try {
            if (this.authOptions.authMethod === AuthMethod.COOKIE) {
                response.cookie(ACCESS_TOKEN_COOKIE_NAME, "", {
                    maxAge: 0,
                    httpOnly: true,
                    sameSite: this.authOptions.cookies.sameSite,
                    secure: this.authOptions.cookies.secure,
                    signed: true,
                    // secure: this.authOptions.app.isProd,
                });
                response.cookie(REFRESH_TOKEN_COOKIE_NAME, "", {
                    maxAge: 0,
                    httpOnly: true,
                    sameSite: this.authOptions.cookies.sameSite,
                    secure: this.authOptions.cookies.secure,
                    signed: true,
                    // secure: this.authOptions.app.isProd,
                });
            }

            const cacheUser = await this.cacheService.getUser(tokenUser.id);
            if ((cacheUser?.sessions?.length || 0) > 1) {
                cacheUser.sessions = cacheUser.sessions.filter(
                    (session) => session.accessToken !== tokenUser.accessToken,
                );
                if (cacheUser.sessions.length) {
                    cacheUser.sessions = cacheUser.sessions.filter((session) => {
                        try {
                            this.jwtTokenService.verifyAccessToken(session.accessToken);
                            return true;
                        } catch {
                            return false;
                        }
                    });
                }
                await this.cacheService.setUser(cacheUser);
            } else {
                await this.cacheService.clearUser(tokenUser.id);
            }

            this.userService.onLogout?.(request, tokenUser).catch();

            return new SuccessResponse("Successfully logged out");
        } catch (err) {
            this.userService.onLogout?.(request, tokenUser, err as Error).catch();
            throw err;
        }
    }
}
