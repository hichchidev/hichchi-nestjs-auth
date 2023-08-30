"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const auth_service_1 = require("../services/auth.service");
const tokens_1 = require("../tokens");
const guards_1 = require("../guards");
const dtos_1 = require("../dtos");
const request_user_decorator_1 = require("../decorators/request-user.decorator");
const jwt_auth_guard_1 = require("../guards/jwt-auth.guard");
const utils_1 = require("hichchi-nestjs-common/utils");
const responses_1 = require("hichchi-nestjs-common/responses");
const cache_1 = require("hichchi-nestjs-common/cache");
const update_password_dto_1 = require("../dtos/update-password.dto");
let AuthController = class AuthController {
    constructor(authOptions, cacheService, authService) {
        this.authOptions = authOptions;
        this.cacheService = cacheService;
        this.authService = authService;
    }
    async register(dto) {
        var _a;
        return this.authService.register(await (0, utils_1.validateDto)((_a = this.authOptions.registerDto) !== null && _a !== void 0 ? _a : dtos_1.RegisterDto, dto));
    }
    async authenticate(user, _loginDto, response) {
        await this.cacheService.setUser(user);
        const tokenResponse = this.authService.generateTokens(user);
        response.cookie(tokens_1.ACCESS_TOKEN_COOKIE_NAME, tokenResponse.accessToken, {
            maxAge: this.authOptions.jwt.expiresIn * 1000,
            httpOnly: true,
            sameSite: this.authOptions.cookies.sameSite,
            signed: true,
        });
        response.cookie(tokens_1.REFRESH_TOKEN_COOKIE_NAME, tokenResponse.refreshToken, {
            maxAge: this.authOptions.jwt.refreshExpiresIn * 1000,
            httpOnly: true,
            sameSite: this.authOptions.cookies.sameSite,
            signed: true,
        });
        return user;
    }
    async getCurrentUser(user) {
        return this.authService.getCurrentUser(user.id);
    }
    changePassword(user, updatePasswordDto) {
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
    async clearAuthentication(user, response) {
        response.cookie(tokens_1.ACCESS_TOKEN_COOKIE_NAME, "", {
            maxAge: 0,
            httpOnly: true,
            sameSite: this.authOptions.cookies.sameSite,
            secure: this.authOptions.cookies.secure,
            signed: true,
            // secure: this.authOptions.app.isProd,
        });
        response.cookie(tokens_1.REFRESH_TOKEN_COOKIE_NAME, "", {
            maxAge: 0,
            httpOnly: true,
            sameSite: this.authOptions.cookies.sameSite,
            secure: this.authOptions.cookies.secure,
            signed: true,
            // secure: this.authOptions.app.isProd,
        });
        await this.cacheService.clearUser(user.id);
        return new responses_1.SuccessResponse("Successfully logged out");
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Post)("register"),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Post)("login"),
    (0, common_1.UseGuards)(guards_1.LocalAuthGuard),
    __param(0, (0, request_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, dtos_1.LoginDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "authenticate", null);
__decorate([
    (0, common_1.Get)("me"),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    __param(0, (0, request_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "getCurrentUser", null);
__decorate([
    (0, common_1.Post)("change-password"),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    __param(0, (0, request_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, update_password_dto_1.UpdatePasswordDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "changePassword", null);
__decorate([
    (0, common_1.Post)("logout"),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    __param(0, (0, request_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "clearAuthentication", null);
exports.AuthController = AuthController = __decorate([
    (0, common_1.Controller)(tokens_1.AUTH_ENDPOINT),
    __param(0, (0, common_1.Inject)(tokens_1.AUTH_OPTIONS)),
    __metadata("design:paramtypes", [Object, cache_1.RedisCacheService,
        auth_service_1.AuthService])
], AuthController);
//# sourceMappingURL=auth.controller.js.map