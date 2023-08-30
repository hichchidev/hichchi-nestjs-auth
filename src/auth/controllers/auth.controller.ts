import { Body, Controller, Get, Inject, Post, Res, UseGuards } from "@nestjs/common";
import { AuthService } from "../services/auth.service";
import { ACCESS_TOKEN_COOKIE_NAME, AUTH_ENDPOINT, AUTH_OPTIONS, REFRESH_TOKEN_COOKIE_NAME } from "../tokens";
import { IAuthOptions, IUserEntity } from "../interfaces";
import { LocalAuthGuard } from "../guards";
import { LoginDto, RegisterDto } from "../dtos";
import { Response } from "express";
import { CurrentUser } from "../decorators/request-user.decorator";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { validateDto } from "hichchi-nestjs-common/utils";
import { SuccessResponse } from "hichchi-nestjs-common/responses";
import { RedisCacheService } from "hichchi-nestjs-common/cache";

@Controller(AUTH_ENDPOINT)
export class AuthController {
    constructor(
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        private cacheService: RedisCacheService,
        private readonly authService: AuthService,
    ) {}

    @Post("register")
    async register(@Body() dto: any): Promise<IUserEntity> {
        return this.authService.register(await validateDto(this.authOptions.registerDto ?? RegisterDto, dto));
    }

    @Post("login")
    @UseGuards(LocalAuthGuard)
    async authenticate(
        @CurrentUser() user: IUserEntity,
        @Body() _loginDto: LoginDto,
        @Res({ passthrough: true }) response: Response,
    ): Promise<IUserEntity> {
        await this.cacheService.setUser(user);
        const tokenResponse = this.authService.generateTokens(user);
        response.cookie(ACCESS_TOKEN_COOKIE_NAME, tokenResponse.accessToken, {
            maxAge: this.authOptions.jwt.expiresIn * 1000,
            httpOnly: true,
            sameSite: this.authOptions.cookies.sameSite,
            signed: true,
        });
        response.cookie(REFRESH_TOKEN_COOKIE_NAME, tokenResponse.refreshToken, {
            maxAge: this.authOptions.jwt.refreshExpiresIn * 1000,
            httpOnly: true,
            sameSite: this.authOptions.cookies.sameSite,
            signed: true,
        });
        return user;
    }

    @Get("me")
    async getCurrentUser(@CurrentUser() user: IUserEntity): Promise<IUserEntity> {
        return this.authService.getCurrentUser(user.id);
    }

    // @Post("verify-account")
    // verifyAccount(@Body() verificationDto: VerificationDto): Promise<SuccessResponse> {
    //     return this.authService.verifyAccount(verificationDto.token);
    // }
    //
    // @UseGuards(JwtAuthGuard)
    // @Get("me")
    // getMe(@ReqUser() user: User): Promise<User> {
    //     return this.authService.getMe(user.id);
    // }
    //
    // @Post("resend-verification")
    // resendVerification(@Body() verificationDto: ResendVerificationDto): Promise<SuccessResponse> {
    //     return this.authService.resendVerification(verificationDto.email);
    // }
    //
    // @UseGuards(JwtAuthGuard)
    // @Post("change-password")
    // changePassword(@ReqUser() user: User, @Body() updatePasswordDto: UpdatePasswordDto): Promise<IStatusResponse> {
    //     return this.authService.changePassword(user.id, updatePasswordDto);
    // }
    //
    // @Post("request-password-reset")
    // requestPasswordReset(@Body() requestResetDto: RequestResetDto): Promise<SuccessResponse> {
    //     return this.authService.requestPasswordReset(requestResetDto);
    // }
    //
    // @Post("reset-password")
    // resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<IStatusResponse> {
    //     return this.authService.resetPassword(resetPasswordDto);
    // }

    @Post("logout")
    @UseGuards(JwtAuthGuard)
    async clearAuthentication(
        @CurrentUser() user: IUserEntity,
        @Res({ passthrough: true }) response: Response,
    ): Promise<SuccessResponse> {
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
        await this.cacheService.clearUser(user.id);
        return new SuccessResponse("Successfully logged out");
    }
}
