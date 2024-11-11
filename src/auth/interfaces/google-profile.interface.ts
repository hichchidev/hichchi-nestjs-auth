import { AuthStrategy } from "../enums/auth-strategies.enum";

export interface IGoogleProfileName {
    givenName: string;
    familyName: string;
}

export interface IGoogleProfilePhoto {
    value: string;
    type: "default";
}

export interface IGoogleProfileEmail {
    value: string;
    type: "account";
}

export interface IGoogleProfileJson {
    sub: string;
    name: string;
    given_name: string;
    family_name: string;
    picture: string;
    email: string;
    email_verified: boolean;
}

export interface IGoogleProfile {
    provider: AuthStrategy.GOOGLE;
    sub: string;
    id: string;
    displayName: string;
    name: IGoogleProfileName;
    given_name: string;
    family_name: string;
    email_verified: boolean;
    verified: boolean;
    email: string;
    emails: IGoogleProfileEmail[];
    photos: IGoogleProfilePhoto[];
    picture: string;
    _raw: string;
    _json: IGoogleProfileJson;
}
