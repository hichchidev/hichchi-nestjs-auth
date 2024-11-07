import { Request } from "express";
import { ACCESS_TOKEN_COOKIE_NAME } from "../tokens";

/**
 * Extract access token from the request cookies
 *
 * This function is used to extract the access token from the request cookies
 *
 * @example
 * ```typescript
 * ExtractJwt.fromExtractors([cookieExtractor])
 * ```
 *
 * @param {Request} request The request object
 * @returns {string|null} Access token or `null` if not found
 */
export function cookieExtractor(request: Request): string | null {
    return request?.signedCookies[ACCESS_TOKEN_COOKIE_NAME] || null;
}
