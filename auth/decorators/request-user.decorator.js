"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CurrentUser = void 0;
const common_1 = require("@nestjs/common");
exports.CurrentUser = (0, common_1.createParamDecorator)((_data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    delete user.password;
    delete user.salt;
    return user;
});
//# sourceMappingURL=request-user.decorator.js.map