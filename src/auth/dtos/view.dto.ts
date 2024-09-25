import { IUserEntity, IViewDto } from "hichchi-nestjs-common/interfaces";
import { PartialWithId } from "hichchi-nestjs-common/types/types";

export class ViewDto implements IViewDto {
    formatDataSet(data: IUserEntity): PartialWithId<IUserEntity> {
        return data;
    }
}
