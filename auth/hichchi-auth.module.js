"use strict";
// noinspection JSUnusedGlobalSymbols
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var HichchiAuthModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.HichchiAuthModule = exports.DEFAULT_SECRET = void 0;
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./services/auth.service");
const jwt_1 = require("@nestjs/jwt");
const passport_1 = require("@nestjs/passport");
const tokens_1 = require("./tokens");
const auth_controller_1 = require("./controllers/auth.controller");
const redisStore = __importStar(require("cache-manager-redis-store"));
const strategies_1 = require("./strategies");
const jwt_strategy_1 = require("./strategies/jwt.strategy");
const jwt_auth_guard_1 = require("./guards/jwt-auth.guard");
const cache_1 = require("hichchi-nestjs-common/cache");
// noinspection SpellCheckingInspection
exports.DEFAULT_SECRET = "3cGnEj4Kd1ENr8UcX8fBKugmv7lXmZyJtsa_fo-RcIk";
let HichchiAuthModule = HichchiAuthModule_1 = class HichchiAuthModule {
    static registerAsync(userServiceProvider, authOptions) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
        // noinspection SpellCheckingInspection
        const options = {
            redis: {
                store: ((_a = authOptions.redis) === null || _a === void 0 ? void 0 : _a.store) || redisStore,
                ttl: ((_b = authOptions.redis) === null || _b === void 0 ? void 0 : _b.ttl) || 10,
                host: ((_c = authOptions.redis) === null || _c === void 0 ? void 0 : _c.host) || "localhost",
                port: ((_d = authOptions.redis) === null || _d === void 0 ? void 0 : _d.port) || 6379,
            },
            jwt: {
                secret: ((_e = authOptions.jwt) === null || _e === void 0 ? void 0 : _e.secret) || exports.DEFAULT_SECRET,
                expiresIn: ((_f = authOptions.jwt) === null || _f === void 0 ? void 0 : _f.expiresIn) || 60 * 60 * 24 * 30,
                refreshSecret: ((_g = authOptions.jwt) === null || _g === void 0 ? void 0 : _g.refreshSecret) || exports.DEFAULT_SECRET,
                refreshExpiresIn: ((_h = authOptions.jwt) === null || _h === void 0 ? void 0 : _h.refreshExpiresIn) || 60 * 60 * 24 * 60,
            },
            cookies: {
                secret: ((_j = authOptions.cookies) === null || _j === void 0 ? void 0 : _j.secret) || ((_k = authOptions.cookies) === null || _k === void 0 ? void 0 : _k.secure) ? exports.DEFAULT_SECRET : undefined,
                sameSite: ((_l = authOptions.cookies) === null || _l === void 0 ? void 0 : _l.sameSite) || "none",
                secure: Boolean((_m = authOptions.cookies) === null || _m === void 0 ? void 0 : _m.secure),
            },
        };
        return {
            module: HichchiAuthModule_1,
            imports: [
                cache_1.RedisCacheModule.registerAsync(options.redis),
                jwt_1.JwtModule.register(options.jwt),
                passport_1.PassportModule,
                ...((_o = userServiceProvider.imports) !== null && _o !== void 0 ? _o : []),
            ],
            providers: [
                {
                    provide: tokens_1.USER_SERVICE,
                    useFactory: userServiceProvider.useFactory,
                    useExisting: userServiceProvider.useExisting,
                    inject: userServiceProvider.inject,
                },
                {
                    provide: tokens_1.AUTH_OPTIONS,
                    useValue: options,
                },
                auth_service_1.AuthService,
                strategies_1.LocalStrategy,
                jwt_strategy_1.JwtStrategy,
                jwt_auth_guard_1.JwtAuthGuard,
                ...((_p = userServiceProvider.inject) !== null && _p !== void 0 ? _p : []),
            ],
            controllers: [auth_controller_1.AuthController],
            exports: [auth_service_1.AuthService, jwt_strategy_1.JwtStrategy, jwt_auth_guard_1.JwtAuthGuard],
        };
    }
};
exports.HichchiAuthModule = HichchiAuthModule;
exports.HichchiAuthModule = HichchiAuthModule = HichchiAuthModule_1 = __decorate([
    (0, common_1.Global)(),
    (0, common_1.Module)({})
], HichchiAuthModule);
//# sourceMappingURL=hichchi-auth.module.js.map