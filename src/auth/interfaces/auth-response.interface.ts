import { ITokenResponse } from "./token-response.interface";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

// noinspection JSUnusedGlobalSymbols
export interface IAuthResponse extends ITokenResponse {
    user: IUserEntity;
}
