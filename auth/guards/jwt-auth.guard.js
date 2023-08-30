"use strict";
// noinspection JSUnusedGlobalSymbols,JSUnusedLocalSymbols
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
exports.JwtAuthGuard = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
const responses_1 = require("../responses");
const passport_jwt_1 = require("passport-jwt");
const tokens_1 = require("../tokens");
const auth_service_1 = require("../services/auth.service");
const cache_1 = require("hichchi-nestjs-common/cache");
const extractors_1 = require("../extractors");
let JwtAuthGuard = class JwtAuthGuard extends (0, passport_1.AuthGuard)("jwt") {
    constructor(authOptions, authService, cacheService) {
        super();
        this.authOptions = authOptions;
        this.authService = authService;
        this.cacheService = cacheService;
    }
    async canActivate(context) {
        const request = context.switchToHttp().getRequest();
        const response = context.switchToHttp().getResponse();
        try {
            const accessToken = passport_jwt_1.ExtractJwt.fromExtractors([extractors_1.cookieExtractor])(request);
            if (accessToken) {
                return this.activate(context);
            }
            const refreshToken = request.signedCookies[tokens_1.REFRESH_TOKEN_COOKIE_NAME];
            if (!refreshToken) {
                return Promise.reject(new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_NOT_LOGGED_IN));
            }
            const user = await this.authService.getUserByToken(refreshToken, true);
            const tokens = this.authService.generateTokens(user);
            await this.cacheService.setUser(user);
            request.signedCookies[tokens_1.ACCESS_TOKEN_COOKIE_NAME] = tokens.accessToken;
            response.cookie(tokens_1.ACCESS_TOKEN_COOKIE_NAME, tokens.refreshToken, {
                maxAge: Number(this.authOptions.jwt.expiresIn) * 1000,
                httpOnly: true,
                sameSite: this.authOptions.cookies.sameSite,
                secure: this.authOptions.cookies.secure,
                signed: true,
            });
            response.cookie(tokens_1.REFRESH_TOKEN_COOKIE_NAME, tokens.refreshToken, {
                maxAge: Number(this.authOptions.jwt.refreshExpiresIn) * 1000,
                httpOnly: true,
                sameSite: this.authOptions.cookies.sameSite,
                secure: this.authOptions.cookies.secure,
                signed: true,
            });
            return this.activate(context);
        }
        catch (err) {
            // LoggerService.error(err);
            response.clearCookie(tokens_1.ACCESS_TOKEN_COOKIE_NAME);
            response.clearCookie(tokens_1.REFRESH_TOKEN_COOKIE_NAME);
            return false;
        }
    }
    activate(context) {
        return super.canActivate(context);
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handleRequest(err, user, _info) {
        // You can throw an exception based on either "info" or "err" arguments
        if (err || !user) {
            throw err || new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_INVALID_TOKEN);
        }
        delete user.password;
        delete user.salt;
        return user;
    }
};
exports.JwtAuthGuard = JwtAuthGuard;
exports.JwtAuthGuard = JwtAuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.AUTH_OPTIONS)),
    __metadata("design:paramtypes", [Object, auth_service_1.AuthService,
        cache_1.RedisCacheService])
], JwtAuthGuard);
//# sourceMappingURL=jwt-auth.guard.js.map