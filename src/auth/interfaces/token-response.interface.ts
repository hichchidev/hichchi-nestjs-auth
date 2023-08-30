import { ITokens } from "./tokens.interface";

export interface ITokenResponse extends ITokens {
    accessTokenExpiresIn: string;
    refreshTokenExpiresIn: string;
}
