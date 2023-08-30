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
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var AuthService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const tokens_1 = require("../tokens");
const crypto_1 = require("crypto");
// import { RedisCacheService } from "../../cache/services/redis-cache.service";
const jwt_1 = require("@nestjs/jwt");
const responses_1 = require("../responses");
let AuthService = AuthService_1 = class AuthService {
    constructor(userService, authOptions, 
    // private readonly cacheService: RedisCacheService,
    jwtService) {
        this.userService = userService;
        this.authOptions = authOptions;
        this.jwtService = jwtService;
    }
    // noinspection JSUnusedGlobalSymbols
    static generateRandomHash() {
        return (0, crypto_1.randomBytes)(48).toString("hex");
    }
    static generatePassword(password) {
        const salt = (0, crypto_1.randomBytes)(32).toString("hex");
        const hash = (0, crypto_1.pbkdf2Sync)(password, salt, 10000, 64, "sha512").toString("hex");
        return { salt, password: hash };
    }
    static verifyHash(password, hash, salt) {
        const generatedHash = (0, crypto_1.pbkdf2Sync)(password, salt, 10000, 64, "sha512").toString("hex");
        return hash === generatedHash;
    }
    generateToken(payload, secret, expiresIn) {
        return this.jwtService.sign(payload, { secret, expiresIn: `${expiresIn}s` });
    }
    async register(registerDto) {
        const { password: rawPass } = registerDto, rest = __rest(registerDto, ["password"]);
        const { password, salt } = AuthService_1.generatePassword(rawPass);
        const user = await this.userService.createUser(Object.assign(Object.assign({}, rest), { password, salt }));
        delete user.password;
        delete user.salt;
        return user;
    }
    async authenticate(username, password) {
        try {
            const user = await this.userService.getUserByUsername(username);
            if (!user) {
                return Promise.reject(new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_INVALID));
            }
            if (!AuthService_1.verifyHash(password, user.password, user.salt)) {
                return Promise.reject(new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_INVALID));
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
        }
        catch (err) {
            // LoggerService.error(err);
            throw new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_INVALID);
        }
    }
    getCurrentUser(id) {
        return this.userService.getUserById(id);
    }
    async changePassword(id, updatePasswordDto) {
        const { password, salt } = await this.userService.getUserById(id);
        const { oldPassword, newPassword } = updatePasswordDto;
        if (AuthService_1.verifyHash(oldPassword, password, salt)) {
            const { password, salt } = AuthService_1.generatePassword(newPassword);
            const user = await this.userService.updateUserById(id, { password, salt });
            delete user.password;
            delete user.salt;
            return user;
        }
        throw new common_1.NotFoundException(responses_1.AuthErrors.AUTH_401_INVALID_PASSWORD);
    }
    generateTokens(user) {
        const payload = {
            sub: user.id,
            username: user.username,
            email: user.email,
        };
        const accessToken = this.generateToken(payload, this.authOptions.jwt.secret, this.authOptions.jwt.expiresIn);
        const refreshToken = this.generateToken(payload, this.authOptions.jwt.refreshSecret, this.authOptions.jwt.refreshExpiresIn);
        return {
            accessToken,
            refreshToken,
            accessTokenExpiresIn: `${this.authOptions.jwt.expiresIn}s`,
            refreshTokenExpiresIn: `${this.authOptions.jwt.refreshExpiresIn}s`,
        };
    }
    verifyToken(token, refresh) {
        return this.jwtService.verify(token, {
            secret: refresh ? this.authOptions.jwt.refreshSecret : this.authOptions.jwt.secret,
        });
    }
    async getUserByToken(bearerToken, refresh) {
        try {
            const payload = this.verifyToken(bearerToken, refresh);
            const user = await this.userService.getUserById(payload.sub);
            if (!user) {
                return null;
            }
            return user;
        }
        catch (err) {
            // LoggerService.error(err);
            return null;
        }
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = AuthService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.USER_SERVICE)),
    __param(1, (0, common_1.Inject)(tokens_1.AUTH_OPTIONS)),
    __metadata("design:paramtypes", [Object, Object, jwt_1.JwtService])
], AuthService);
//# sourceMappingURL=auth.service.js.map