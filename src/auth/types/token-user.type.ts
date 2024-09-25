import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { ITokens } from "../interfaces";
import { ISocketId } from "../interfaces/socket-id.interface";

export type TokenUser = Omit<IUserEntity, "password" | "salt"> & ITokens & ISocketId;
