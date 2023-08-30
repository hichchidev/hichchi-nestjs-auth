import { IUserEntity } from "./user-entity.interface";
import { ITokenResponse } from "./token-response.interface";

// noinspection JSUnusedGlobalSymbols
export interface IAuthResponse {
    tokens: ITokenResponse;
    user: IUserEntity;
}
