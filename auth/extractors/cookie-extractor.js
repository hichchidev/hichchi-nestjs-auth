"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cookieExtractor = void 0;
const tokens_1 = require("../tokens");
const cookieExtractor = (request) => {
    return (request === null || request === void 0 ? void 0 : request.signedCookies[tokens_1.ACCESS_TOKEN_COOKIE_NAME]) || null;
};
exports.cookieExtractor = cookieExtractor;
//# sourceMappingURL=cookie-extractor.js.map