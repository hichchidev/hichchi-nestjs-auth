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
exports.JwtStrategy = void 0;
const passport_jwt_1 = require("passport-jwt");
const passport_1 = require("@nestjs/passport");
const common_1 = require("@nestjs/common");
const responses_1 = require("../responses");
const tokens_1 = require("../tokens");
const extractors_1 = require("../extractors");
let JwtStrategy = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy) {
    constructor(userService, authOptions) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromExtractors([extractors_1.cookieExtractor]),
            ignoreExpiration: false,
            secretOrKey: authOptions.jwt.secret,
        });
        this.userService = userService;
    }
    // noinspection JSUnusedGlobalSymbols
    async validate(jwtPayload) {
        try {
            const user = await this.userService.getUserById(jwtPayload.sub);
            if (!user) {
                return Promise.reject(new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_INVALID_TOKEN));
            }
            return user;
        }
        catch (err) {
            // LoggerService.error(err);
            return Promise.reject(new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_INVALID_TOKEN));
        }
    }
};
exports.JwtStrategy = JwtStrategy;
exports.JwtStrategy = JwtStrategy = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.USER_SERVICE)),
    __param(1, (0, common_1.Inject)(tokens_1.AUTH_OPTIONS)),
    __metadata("design:paramtypes", [Object, Object])
], JwtStrategy);
//# sourceMappingURL=jwt.strategy.js.map