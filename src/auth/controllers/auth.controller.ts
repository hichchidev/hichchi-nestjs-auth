import { Body, Controller, ForbiddenException, Get, HttpCode, Inject, Post, Req, Res, UseGuards } from "@nestjs/common";
import { AuthService } from "../services";
import { AUTH_ENDPOINT, AUTH_OPTIONS } from "../tokens";
import { IAuthOptions, IAuthResponse } from "../interfaces";
import { JwtAuthGuard, LocalAuthGuard } from "../guards";
import { LoginDto, RefreshTokenDto, RequestResetDto, UpdatePasswordDto } from "../dtos";
import { Request, Response } from "express";
import { CurrentUser } from "../decorators";
import { validateDto } from "hichchi-nestjs-common/utils";
import { SuccessResponse } from "hichchi-nestjs-common/responses";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { TokenUser } from "../types";
import { AuthErrors } from "../responses";
import { ResetPasswordTokenVerifyDto } from "../dtos/reset-password-token-verify.dto";
import { ResetPasswordDto } from "../dtos/reset-password.dto";

@Controller(AUTH_ENDPOINT)
export class AuthController {
    constructor(
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        private readonly authService: AuthService,
    ) {}

    @Post("register")
    @HttpCode(201)
    async register(@Req() request: Request, @Body() dto: any): Promise<IUserEntity> {
        if (this.authOptions.disableRegistration) {
            throw new ForbiddenException(AuthErrors.USER_403_REGISTER);
        }
        return this.authService.register(request, await validateDto(this.authOptions.registerDto, dto));
    }

    @Post("login")
    @HttpCode(200)
    @UseGuards(LocalAuthGuard)
    async login(
        @Req() request: Request,
        @CurrentUser() tokenUser: TokenUser,
        @Body() _loginDto: LoginDto,
        @Res({ passthrough: true }) response: Response,
    ): Promise<IAuthResponse> {
        return this.authService.login(request, tokenUser, response);
    }

    @Post("refresh-token")
    @HttpCode(201)
    refreshTokens(
        @Req() request: Request,
        @Body() refreshTokenDto: RefreshTokenDto,
        @Res({ passthrough: true }) response: Response,
    ): Promise<any> {
        return this.authService.refreshTokens(request, refreshTokenDto.refreshToken, response);
    }

    @Get("me")
    @HttpCode(200)
    @UseGuards(JwtAuthGuard)
    async getCurrentUser(@Req() request: Request, @CurrentUser() tokenUser: TokenUser): Promise<IUserEntity> {
        return this.authService.getCurrentUser(request, tokenUser);
    }

    @Post("change-password")
    @HttpCode(201)
    @UseGuards(JwtAuthGuard)
    changePassword(
        @Req() request: Request,
        @CurrentUser() tokenUser: TokenUser,
        @Body() updatePasswordDto: UpdatePasswordDto,
    ): Promise<IUserEntity> {
        return this.authService.changePassword(request, tokenUser, updatePasswordDto);
    }

    // @Post("verify-account")
    // verifyAccount(@Body() verificationDto: VerificationDto): Promise<SuccessResponse> {
    //     return this.authService.verifyAccount(verificationDto.token);
    // }
    //
    // @Post("resend-verification")
    // resendVerification(@Body() verificationDto: ResendVerificationDto): Promise<SuccessResponse> {
    //     return this.authService.resendVerification(verificationDto.email);
    // }

    @Post("request-password-reset")
    requestPasswordReset(@Req() request: Request, @Body() requestResetDto: RequestResetDto): Promise<SuccessResponse> {
        return this.authService.requestPasswordReset(request, requestResetDto);
    }

    @Post("reset-password-verify")
    verifyResetPasswordToken(
        @Req() request: Request,
        @Body() verifyDto: ResetPasswordTokenVerifyDto,
    ): Promise<SuccessResponse> {
        return this.authService.verifyResetPasswordToken(request, verifyDto);
    }

    @Post("reset-password")
    resetPassword(@Req() request: Request, @Body() resetPasswordDto: ResetPasswordDto): Promise<SuccessResponse> {
        return this.authService.resetPassword(request, resetPasswordDto);
    }

    @Post("logout")
    @HttpCode(200)
    @UseGuards(JwtAuthGuard)
    async logout(
        @Req() request: Request,
        @CurrentUser() tokenUser: TokenUser,
        @Res({ passthrough: true }) response: Response,
    ): Promise<SuccessResponse> {
        return this.authService.logout(request, tokenUser, response);
    }
}
