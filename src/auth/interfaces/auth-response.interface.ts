import { ITokenResponse } from "./token-response.interface";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

// noinspection JSUnusedGlobalSymbols
export interface IAuthResponse {
    tokens: ITokenResponse;
    user: IUserEntity;
}
