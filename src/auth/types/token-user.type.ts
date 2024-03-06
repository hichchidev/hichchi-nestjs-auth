import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { ITokens } from "../interfaces";

export type TokenUser = Omit<IUserEntity, "password" | "salt"> & ITokens;
