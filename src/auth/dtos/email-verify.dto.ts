import { IsNotEmpty } from "class-validator";
import { toErrString } from "hichchi-nestjs-common/converters";
import { AuthErrors } from "../responses";

export class EmailVerifyDto {
    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_TOKEN))
    token: string;
}
