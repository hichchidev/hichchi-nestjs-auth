// noinspection JSUnusedGlobalSymbols

import { Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
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
import { UpdatePasswordDto } from "../dtos";
import { AuthField, AuthMethod } from "../enums";
import { Response } from "express";
import { UserCacheService } from "./user-cache.service";
import { JwtTokenService } from "./jwt-token.service";
import { LoggerService } from "hichchi-nestjs-common/services";
import { SuccessResponse } from "hichchi-nestjs-common/responses";
import { TokenUser } from "../types";
import { v4 as uuid } from "uuid";

@Injectable()
export class AuthService {
    constructor(
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        @Inject(USER_SERVICE) private userService: IUserService,
        private readonly cacheService: UserCacheService,
        private readonly jwtTokenService: JwtTokenService,
    ) {}

    /**
     * Generate a random hash
     * @returns {string} Random hash
     */
    public static generateRandomHash(): string {
        return randomBytes(48).toString("hex");
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
     * Register a new user
     * @param {IRegisterDto} registerDto Register DTO
     * @returns {Promise<IUserEntity>} Registered user
     */
    async register(registerDto: IRegisterDto): Promise<IUserEntity> {
        const { password: rawPass, ...rest } = registerDto;
        const { password, salt } = AuthService.generatePassword(rawPass);
        const user = await this.userService.registerUser({ ...rest, password, salt });
        delete user.password;
        delete user.salt;
        return user;
    }

    /**
     * Authenticate a user
     * @param {string} username Username or email
     * @param {string} password Password
     * @param {string} subdomain Subdomain
     * @returns {Promise<IUserEntity>} Authenticated user
     */
    async authenticate(username: string, password: string, subdomain?: string): Promise<IUserEntity> {
        const INVALID_CREDS =
            this.authOptions.authField === AuthField.EMAIL
                ? AuthErrors.AUTH_401_INVALID_EMAIL_PASSWORD
                : AuthErrors.AUTH_401_INVALID_UNAME_PASSWORD;

        try {
            const user =
                this.authOptions.authField === AuthField.USERNAME
                    ? await this.userService.getUserByUsername(username, subdomain)
                    : this.authOptions.authField === AuthField.EMAIL
                      ? await this.userService.getUserByEmail(username, subdomain)
                      : await this.userService.getUserByUsernameOrEmail(username, subdomain);

            if (!user) {
                return Promise.reject(new UnauthorizedException(INVALID_CREDS));
            }
            if (!AuthService.verifyHash(password, user.password, user.salt)) {
                return Promise.reject(new UnauthorizedException(INVALID_CREDS));
            }
            // if (user.status === Status.PENDING) {
            //     return Promise.reject(new ForbiddenException(AuthErrors.AUTH_403_PENDING));
            // }
            // if (user.status !== Status.ACTIVE) {
            //     return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_NOT_ACTIVE));
            // }
            delete user.password;
            delete user.salt;
            return user;
        } catch (err) {
            LoggerService.error(err);
            throw new UnauthorizedException(INVALID_CREDS);
        }
    }

    /**
     * Login a user
     * @param {IUserEntity} user User entity
     * @param {Response} response Response object
     * @returns {Promise<IAuthResponse>} Auth response
     */
    async login(user: IUserEntity, response: Response): Promise<IAuthResponse> {
        const tokenResponse = this.generateTokens(user);

        await this.updateCacheUser(user, tokenResponse);

        this.setAuthCookies(response, tokenResponse);

        return {
            ...tokenResponse,
            user,
        };
    }

    /**
     * Refresh the tokens
     * @param token Refresh token
     * @param response Response object
     * @returns {Promise<ITokenResponse>} Token response
     */
    async refreshTokens(token: string, response: Response): Promise<ITokenResponse> {
        try {
            const { sub } = this.jwtTokenService.verifyRefreshToken(token);

            const user = await this.userService.getUserById(sub);
            if (!user) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_REFRESH_TOKEN));
            }

            const tokenResponse: ITokenResponse = this.generateTokens(user);

            await this.updateCacheUser(user, tokenResponse, token);

            this.setAuthCookies(response, tokenResponse);

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
     * Update the cache user
     * @param user User entity
     * @param tokenResponse Token response
     * @param oldRefreshToken Old refresh token
     */
    async updateCacheUser(user: IUserEntity, tokenResponse: ITokenResponse, oldRefreshToken?: string): Promise<void> {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { password, salt, ...rest } = new this.authOptions.viewDto().formatDataSet(user);
        const cacheUser: ICacheUser = { ...rest, sessions: (await this.cacheService.getUser(user.id))?.sessions ?? [] };

        if (cacheUser.sessions.length) {
            cacheUser.sessions = cacheUser.sessions.filter((session) => session.refreshToken !== oldRefreshToken);
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
     * Validate a user using JWT
     * @param {IJwtPayload} payload JWT payload
     * @param {string} accessToken Access token
     * @param {boolean} logout Logout status
     * @returns {Promise<TokenUser>} Token user
     */
    async validateUserUsingJWT(payload: IJwtPayload, accessToken: string, logout: boolean): Promise<TokenUser> {
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

        const { sessions, ...user } = cacheUser;

        const session = sessions.find((s) => s.accessToken === accessToken);

        return {
            ...user,
            sessionId: session.sessionId,
            accessToken: session.accessToken,
            refreshToken: session.refreshToken,
        };
    }

    /**
     * Get a user by ID
     * @param {string|number} id User ID
     * @returns {Promise<IUserEntity>} Current user
     */
    getUserById(id: string | number): Promise<IUserEntity> {
        return this.userService.getUserById(id);
    }

    /**
     * Change user password
     * @param {number} id User ID
     * @param {UpdatePasswordDto} updatePasswordDto Update password DTO
     * @param {IUserEntity} updatedBy Updated by user
     * @returns {Promise<IUserEntity>} Updated user
     */
    async changePassword(
        id: string | number,
        updatePasswordDto: UpdatePasswordDto,
        updatedBy: IUserEntity,
    ): Promise<IUserEntity> {
        const { password, salt } = await this.userService.getUserById(id);
        const { oldPassword, newPassword } = updatePasswordDto;
        if (AuthService.verifyHash(oldPassword, password, salt)) {
            const { password, salt } = AuthService.generatePassword(newPassword);
            const user = await this.userService.updateUserById(id, { password, salt }, updatedBy);
            delete user.password;
            delete user.salt;
            return user;
        }
        throw new NotFoundException(AuthErrors.AUTH_401_INVALID_PASSWORD);
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

    // async verifyAccount(token: string): Promise<SuccessResponse> {
    //     const verification = await this.verificationService.getOne({
    //         where: { token, type: VerificationType.EMAIL },
    //         relations: ["user"],
    //     });
    //     if (verification) {
    //         await this.userService.update(verification.user.id, { status: Status.ACTIVE });
    //         await this.verificationService.deleteToken(verification.id);
    //         return new SuccessResponse("Account verified successfully");
    //     }
    //     throw new NotFoundException(AuthErrors.AUTH_401_INVALID_VERIFICATION_TOKEN);
    // }

    // async resendVerification(email: string): Promise<SuccessResponse> {
    //     try {
    //         const user = await this.userService.getOne({ where: { email } });
    //         if (user) {
    //             if (user.status === Status.ACTIVE) {
    //                 return Promise.reject(new BadRequestException(AuthErrors.AUTH_400_ALREADY_VERIFIED));
    //             }
    //             try {
    //                 const verification = await this.verificationService.getOne({
    //                     where: { user: { id: user.id }, type: VerificationType.EMAIL },
    //                 });
    //                 await this.verificationService.deleteToken(verification.id);
    //             } catch (err) {
    //                 if (!(err instanceof NotFoundException)) {
    //                     return Promise.reject(err);
    //                 }
    //             }
    //             await this.sendVerificationEmail(user);
    //             return new SuccessResponse("Verification email sent successfully");
    //         }
    //         return Promise.reject(new NotFoundException(AuthErrors.AUTH_404_EMAIL));
    //     } catch (err) {
    //         if (err instanceof NotFoundException) {
    //             throw new NotFoundException(AuthErrors.AUTH_404_EMAIL);
    //         }
    //         throw err;
    //     }
    // }

    // async sendVerificationEmail(user: IUserEntity): Promise<void> {
    //     const token = AuthService.generateRandomHash();
    //     await this.verificationService.save({ user, token, type: VerificationType.EMAIL });
    //     await this.emailService.sendVerificationEmail(user.email, user.name, token);
    // }

    // async requestPasswordReset(requestResetDto: RequestResetDto): Promise<SuccessResponse> {
    //     // eslint-disable-next-line @typescript-eslint/no-unused-vars
    //     try {
    //         const user = await this.userService.getOne({ where: { email: requestResetDto.email } });
    //         if (user) {
    //             const token = AuthService.generateRandomHash();
    //             await this.verificationService.save({ user, token, type: VerificationType.PASSWORD_RESET });
    //             await this.emailService.sendPasswordResetEmail(user.email, user.name, token);
    //             return new SuccessResponse("Password reset email sent successfully");
    //         }
    //     } catch (err) {
    //         if (err instanceof NotFoundException) {
    //             throw new NotFoundException(AuthErrors.AUTH_404_EMAIL);
    //         }
    //         throw err;
    //     }
    // }

    // resetPassword(resetPasswordDto: ResetPasswordDto): Promise<IStatusResponse> {
    //     return this.userService.transaction(async (manager: EntityManager): Promise<IStatusResponse> => {
    //         try {
    //             const { token, password } = resetPasswordDto;
    //             const verification = await this.verificationService.getOne(
    //                 {
    //                     where: { token, type: VerificationType.PASSWORD_RESET },
    //                     relations: ["user"],
    //                 },
    //                 manager,
    //             );
    //             if (verification) {
    //                 const { password: passwordHash, salt } = AuthService.generatePassword(password);
    //                 await this.userService.update(verification.userId, { password: passwordHash, salt }, null, manager);
    //                 await this.verificationService.deleteToken(verification.id, manager);
    //                 return EntityUtils.handleSuccess(Operation.UPDATE, "user");
    //             }
    //         } catch {
    //             throw new NotFoundException(AuthErrors.AUTH_401_INVALID_PASSWORD_RESET_TOKEN);
    //         }
    //     });
    // }

    /**
     * Logout a user
     * @param {TokenUser} user User entity
     * @param {Response} response Response object
     * @returns {Promise<SuccessResponse>} Success response
     */
    async logout(user: TokenUser, response: Response): Promise<SuccessResponse> {
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

        const cacheUser = await this.cacheService.getUser(user.id);
        if ((cacheUser?.sessions?.length || 0) > 1) {
            cacheUser.sessions = cacheUser.sessions.filter((session) => session.accessToken !== user.accessToken);
            if (cacheUser.sessions.length) {
                cacheUser.sessions = cacheUser.sessions.filter((session) => {
                    try {
                        this.jwtTokenService.verifyAccessToken(session.accessToken);
                        return true;
                    } catch (error) {
                        return false;
                    }
                });
            }
            await this.cacheService.setUser(cacheUser);
        } else {
            await this.cacheService.clearUser(user.id);
        }

        return new SuccessResponse("Successfully logged out");
    }
}
