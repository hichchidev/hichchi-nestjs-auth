import { IUserEntity, IViewDto } from "hichchi-nestjs-common/interfaces";

export class ViewDto implements IViewDto {
    formatDataSet(user: IUserEntity): IUserEntity {
        return user;
    }
}
