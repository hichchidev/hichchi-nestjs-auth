import { Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import {
    IAuthOptions,
    IAuthResponse,
    ICacheUser,
    IRegisterDto,
    IJwtPayload,
    ITokenResponse,
    IUserService,
} from "../interfaces";
import { ACCESS_TOKEN_COOKIE_NAME, AUTH_OPTIONS, REFRESH_TOKEN_COOKIE_NAME, USER_SERVICE } from "../tokens";
import { pbkdf2Sync, randomBytes } from "crypto";
import { TokenExpiredError } from "@nestjs/jwt";
import { AuthErrors } from "../responses";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { UpdatePasswordDto } from "../dtos/update-password.dto";
import { AuthBy } from "../enums/auth-by.enum";
import { AuthType } from "../enums/auth-type.enum";
import { Response } from "express";
import { UserCacheService } from "./user-cache.service";
import { JwtTokenService } from "./jwt-token.service";
import { LoggerService } from "hichchi-nestjs-common/services";
import { SuccessResponse } from "hichchi-nestjs-common/responses";
import { TokenUser } from "../types/token-user.type";

@Injectable()
export class AuthService {
    constructor(
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        @Inject(USER_SERVICE) private userService: IUserService,
        private readonly cacheService: UserCacheService,
        private readonly jwtTokenService: JwtTokenService,
    ) {}

    // noinspection JSUnusedGlobalSymbols
    public static generateRandomHash(): string {
        return randomBytes(48).toString("hex");
    }

    public static generatePassword(password: string): { salt: string; password: string } {
        const salt = randomBytes(32).toString("hex");
        const hash = pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
        return { salt, password: hash };
    }

    public static verifyHash(password: string, hash: string, salt: string): boolean {
        const generatedHash = pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
        return hash === generatedHash;
    }

    async register(registerDto: IRegisterDto): Promise<IUserEntity> {
        const { password: rawPass, ...rest } = registerDto;
        const { password, salt } = AuthService.generatePassword(rawPass);
        const user = await this.userService.createUser({ ...rest, password, salt });
        delete user.password;
        delete user.salt;
        return user;
    }

    async authenticate(username: string, password: string): Promise<IUserEntity> {
        try {
            // eslint-disable-next-line no-console
            // console.log("hichchi-nestjs-auth => authOptions: ", this.authOptions);

            const user =
                this.authOptions.authBy === AuthBy.USERNAME
                    ? await this.userService.getUserByUsername(username)
                    : this.authOptions.authBy === AuthBy.EMAIL
                      ? await this.userService.getUserByEmail(username)
                      : await this.userService.getUserByUsernameOrEmail(username);

            if (!user) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID));
            }
            if (!AuthService.verifyHash(password, user.password, user.salt)) {
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID));
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
        } catch (err: any) {
            LoggerService.error(err);
            throw new UnauthorizedException(AuthErrors.AUTH_401_INVALID);
        }
    }

    async login(user: IUserEntity, response: Response): Promise<IAuthResponse> {
        const tokenResponse = this.generateTokens(user);

        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { password, salt, ...rest } = user;
        const cacheUser: ICacheUser = (await this.cacheService.getUser(user.id)) ?? { ...rest, sessions: [] };

        if (cacheUser.sessions.length) {
            cacheUser.sessions.push({
                accessToken: tokenResponse.accessToken,
                refreshToken: tokenResponse.refreshToken,
            });
        } else {
            cacheUser.sessions = [{ accessToken: tokenResponse.accessToken, refreshToken: tokenResponse.refreshToken }];
        }

        await this.cacheService.setUser(cacheUser);

        if (this.authOptions.authType === AuthType.COOKIE) {
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
        return {
            ...tokenResponse,
            user,
        };
    }

    async validateUserUsingJWT(payload: IJwtPayload, accessToken: string, logout: boolean): Promise<TokenUser> {
        try {
            this.jwtTokenService.verifyAccessToken(accessToken);
        } catch (err) {
            if (err instanceof TokenExpiredError) {
                if (logout) {
                    return { id: payload.sub } as TokenUser;
                }
                return Promise.reject(new UnauthorizedException(AuthErrors.AUTH_401_INVALID_TOKEN));
            }
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
            accessToken: session.accessToken,
            refreshToken: session.refreshToken,
        };
    }

    getCurrentUser(id: number): Promise<IUserEntity> {
        return this.userService.getUserById(id);
    }

    async changePassword(id: number, updatePasswordDto: UpdatePasswordDto): Promise<IUserEntity> {
        const { password, salt } = await this.userService.getUserById(id);
        const { oldPassword, newPassword } = updatePasswordDto;
        if (AuthService.verifyHash(oldPassword, password, salt)) {
            const { password, salt } = AuthService.generatePassword(newPassword);
            const user = await this.userService.updateUserById(id, { password, salt });
            delete user.password;
            delete user.salt;
            return user;
        }
        throw new NotFoundException(AuthErrors.AUTH_401_INVALID_PASSWORD);
    }

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
        } catch (err: any) {
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

    async logout(user: TokenUser, response: Response): Promise<SuccessResponse> {
        if (this.authOptions.authType === AuthType.COOKIE) {
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
            await this.cacheService.setUser(cacheUser);
        } else {
            await this.cacheService.clearUser(user.id);
        }

        return new SuccessResponse("Successfully logged out");
    }
}
