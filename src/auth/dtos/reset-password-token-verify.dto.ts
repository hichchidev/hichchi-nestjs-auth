import { IsNotEmpty } from "class-validator";

export class ResetPasswordTokenVerifyDto {
    @IsNotEmpty()
    token: string;
}
