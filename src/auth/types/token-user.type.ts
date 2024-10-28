import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { ISocketId } from "../interfaces/socket-id.interface";
import { IUserSession } from "../interfaces";

export type TokenUser = Omit<IUserEntity, "password" | "salt"> & IUserSession & ISocketId;
