import { Body, Controller, Get, Inject, Post, Res, UseGuards } from "@nestjs/common";
import { AuthService } from "../services/auth.service";
import { AUTH_ENDPOINT, AUTH_OPTIONS } from "../tokens";
import { IAuthOptions, IAuthResponse } from "../interfaces";
import { LocalAuthGuard } from "../guards";
import { LoginDto, RegisterDto } from "../dtos";
import { Response } from "express";
import { CurrentUser } from "../decorators/request-user.decorator";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { validateDto } from "hichchi-nestjs-common/utils";
import { SuccessResponse } from "hichchi-nestjs-common/responses";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { UpdatePasswordDto } from "../dtos/update-password.dto";
import { TokenUser } from "../types/token-user.type";

@Controller(AUTH_ENDPOINT)
export class AuthController {
    constructor(
        @Inject(AUTH_OPTIONS) private authOptions: IAuthOptions,
        private readonly authService: AuthService,
    ) {}

    @Post("register")
    async register(@Body() dto: any): Promise<IUserEntity> {
        return this.authService.register(await validateDto(this.authOptions.registerDto ?? RegisterDto, dto));
    }

    @Post("login")
    @UseGuards(LocalAuthGuard)
    async login(
        @CurrentUser() user: IUserEntity,
        @Body() _loginDto: LoginDto,
        @Res({ passthrough: true }) response: Response,
    ): Promise<IAuthResponse> {
        return this.authService.login(user, response);
    }

    @Get("me")
    @UseGuards(JwtAuthGuard)
    async getCurrentUser(@CurrentUser() user: TokenUser): Promise<IUserEntity> {
        return this.authService.getCurrentUser(user.id);
    }

    @Post("change-password")
    @UseGuards(JwtAuthGuard)
    changePassword(@CurrentUser() user: TokenUser, @Body() updatePasswordDto: UpdatePasswordDto): Promise<IUserEntity> {
        return this.authService.changePassword(user.id, updatePasswordDto);
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
        @CurrentUser() user: TokenUser,
        @Res({ passthrough: true }) response: Response,
    ): Promise<SuccessResponse> {
        return this.authService.logout(user, response);
    }
}
