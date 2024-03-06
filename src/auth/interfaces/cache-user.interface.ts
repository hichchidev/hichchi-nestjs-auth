import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { IUserSession } from "./user-session.interface";

export interface ICacheUser extends Omit<IUserEntity, "password" | "salt"> {
    sessions: IUserSession[];
}
