import { IsNotEmpty, IsString } from "class-validator";
import { IRegisterDto } from "../interfaces";

export class RegisterDto implements IRegisterDto {
    @IsString()
    @IsNotEmpty()
    username: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}
