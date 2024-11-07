import {
    Body,
    Controller,
    ForbiddenException,
    Get,
    HttpCode,
    Inject,
    Post,
    Query,
    Req,
    Res,
    UseGuards,
} from "@nestjs/common";
import { AuthService } from "../services";
import { AUTH_ENDPOINT, AUTH_OPTIONS } from "../tokens";
import { IAuthOptions, IAuthResponse } from "../interfaces";
import { JwtAuthGuard, LocalAuthGuard } from "../guards";
import {
    EmailVerifyDto,
    LoginDto,
    RefreshTokenDto,
    RequestResetDto,
    ResendEmailVerifyDto,
    ResetPasswordDto,
    ResetPasswordTokenVerifyDto,
    UpdatePasswordDto,
} from "../dtos";
import { Request, Response } from "express";
import { CurrentUser } from "../decorators";
import { validateDto } from "hichchi-nestjs-common/utils";
import { SuccessResponse } from "hichchi-nestjs-common/responses";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { TokenUser } from "../types";
import { AuthErrors } from "../responses";

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
    @HttpCode(200)
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
    @HttpCode(200)
    @UseGuards(JwtAuthGuard)
    changePassword(
        @Req() request: Request,
        @CurrentUser() tokenUser: TokenUser,
        @Body() updatePasswordDto: UpdatePasswordDto,
    ): Promise<IUserEntity> {
        return this.authService.changePassword(request, tokenUser, updatePasswordDto);
    }

    @Post("resend-email-verify")
    @HttpCode(200)
    resendEmailVerification(
        @Req() request: Request,
        @Body() resendEmailVerifyDto: ResendEmailVerifyDto,
    ): Promise<SuccessResponse> {
        return this.authService.resendEmailVerification(request, resendEmailVerifyDto);
    }

    @Get("verify-email")
    @HttpCode(200)
    async verifyEmail(
        @Req() request: Request,
        @Res() response: Response,
        @Query() emailVerifyDto: EmailVerifyDto,
    ): Promise<void> {
        const verified = await this.authService.verifyEmail(request, emailVerifyDto);
        response.redirect(`${this.authOptions.emailVerifyRedirect}?verified=${verified}`);
    }

    @Post("request-password-reset")
    @HttpCode(200)
    requestPasswordReset(@Req() request: Request, @Body() requestResetDto: RequestResetDto): Promise<SuccessResponse> {
        return this.authService.requestPasswordReset(request, requestResetDto);
    }

    @Post("reset-password-verify")
    @HttpCode(200)
    verifyResetPasswordToken(
        @Req() request: Request,
        @Body() verifyDto: ResetPasswordTokenVerifyDto,
    ): Promise<SuccessResponse> {
        return this.authService.verifyResetPasswordToken(request, verifyDto);
    }

    @Post("reset-password")
    @HttpCode(200)
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
