import { Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { IAuthOptions, IRegisterDto, ITokenResponse, IUserService, ITokenData } from "../interfaces";
import { AUTH_OPTIONS, USER_SERVICE } from "../tokens";
import { pbkdf2Sync, randomBytes } from "crypto";
// import { RedisCacheService } from "../../cache/services/redis-cache.service";
import { JwtService } from "@nestjs/jwt";
import { AuthErrors } from "../responses";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { UpdatePasswordDto } from "../dtos/update-password.dto";

@Injectable()
export class AuthService {
    constructor(
        @Inject(USER_SERVICE) private userService: IUserService,
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        // private readonly cacheService: RedisCacheService,
        private readonly jwtService: JwtService,
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

    public generateToken(payload: ITokenData, secret: string, expiresIn: number): string {
        return this.jwtService.sign(payload, { secret, expiresIn: `${expiresIn}s` });
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
            const user = await this.userService.getUserByUsername(username);
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
            // LoggerService.error(err);
            throw new UnauthorizedException(AuthErrors.AUTH_401_INVALID);
        }
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
        const payload: ITokenData = {
            sub: user.id,
            username: user.username,
            email: user.email,
        };
        const accessToken: string = this.generateToken(
            payload,
            this.authOptions.jwt.secret,
            this.authOptions.jwt.expiresIn,
        );

        const refreshToken: string = this.generateToken(
            payload,
            this.authOptions.jwt.refreshSecret,
            this.authOptions.jwt.refreshExpiresIn,
        );
        return {
            accessToken,
            refreshToken,
            accessTokenExpiresIn: `${this.authOptions.jwt.expiresIn}s`,
            refreshTokenExpiresIn: `${this.authOptions.jwt.refreshExpiresIn}s`,
        };
    }

    public verifyToken(token: string, refresh?: boolean): { sub: number; email: number } {
        return this.jwtService.verify(token, {
            secret: refresh ? this.authOptions.jwt.refreshSecret : this.authOptions.jwt.secret,
        });
    }

    public async getUserByToken(bearerToken: string, refresh?: boolean): Promise<IUserEntity> {
        try {
            const payload = this.verifyToken(bearerToken, refresh);
            const user = await this.userService.getUserById(payload.sub);
            if (!user) {
                return null;
            }
            return user;
        } catch (err: any) {
            // LoggerService.error(err);
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
}
