import { IsNotEmpty } from "class-validator";
import { toErrString } from "hichchi-nestjs-common/converters";
import { AuthErrors } from "../responses";

export class UpdatePasswordDto {
    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_OLD_PASSWORD))
    oldPassword?: string;

    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_NEW_PASSWORD))
    newPassword?: string;
}
