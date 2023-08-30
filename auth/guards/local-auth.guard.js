"use strict";
// noinspection JSUnusedGlobalSymbols
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalAuthGuard = void 0;
const passport_1 = require("@nestjs/passport");
const common_1 = require("@nestjs/common");
const responses_1 = require("../responses");
let LocalAuthGuard = class LocalAuthGuard extends (0, passport_1.AuthGuard)("local") {
    canActivate(context) {
        return super.canActivate(context);
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handleRequest(err, user, _info) {
        // You can throw an exception based on either "info" or "err" arguments
        if (err || !user) {
            throw err || new common_1.UnauthorizedException(responses_1.AuthErrors.AUTH_401_NOT_LOGGED_IN);
        }
        delete user.password;
        delete user.salt;
        return user;
    }
};
exports.LocalAuthGuard = LocalAuthGuard;
exports.LocalAuthGuard = LocalAuthGuard = __decorate([
    (0, common_1.Injectable)()
], LocalAuthGuard);
//# sourceMappingURL=local-auth.guard.js.map