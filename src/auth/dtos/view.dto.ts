import { IUserEntity, IViewDto } from "hichchi-nestjs-common/interfaces";
import { PartialWithId } from "hichchi-nestjs-common/types/types";

export class ViewDto implements IViewDto {
    formatDataSet(user: IUserEntity): PartialWithId<IUserEntity> {
        return user;
    }
}
