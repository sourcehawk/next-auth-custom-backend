import type { User, UserObject } from "next-auth";

declare module "next-auth" {
  /**
   * What user information we expect to extract to be able to extract
   * from our backend response
   */
  export interface UserObject {
    id: number;
    email: string;
    name: string;
  }

  /**
   * The contents of our refresh call to the backend is a new access token
   */
  export interface BackendAccessJWT {
    access: string;
  }

  /**
   * The initial backend authentication response contains both an `access` token and a `refresh` token.\
   * The refresh token is a long-lived token that is used to obtain a new access token\
   * when the current access token expires
   */
  export interface BackendJWT extends BackendAccessJWT {
    refresh: string;
  }

  /**
   * The decoded contents of a JWT token returned from the backend (both access and refresh tokens).\
   * It contains both the user information and other token metadata.\
   * `iat` is the time the token was issued, `exp` is the time the token expires, `jti` is the token id.
   */
  export interface DecodedJWT extends UserObject {
    token_type: "refresh" | "access";
    exp: number;
    iat: number;
    jti: string;
  }

  /**
   * Information extracted from our decoded backend tokens so that we don't need to decode them again.\
   * `valid_until` is the time the access token becomes invalid\
   * `refresh_until` is the time the refresh token becomes invalid
   */
  export interface AuthValidity {
    valid_until: number;
    refresh_until: number;
  }

  /**
   * The returned data from the authorize method
   * This is data we extract from our own backend JWT tokens.
   */
  export interface User {
    tokens: BackendJWT;
    user: UserObject;
    validity: AuthValidity;
  }

  /**
   * Returned by `useSession`, `getSession`, returned by the `session` callback and also the shape
   * received as a prop on the SessionProvider React Context
   */
  export interface Session {
    user: UserObject;
    validity: AuthValidity;
    error: "RefreshTokenExpired" | "RefreshAccessTokenError";
  }
}

declare module "next-auth/jwt" {
  /**
   * Returned by the `jwt` callback and `getToken`, when using JWT sessions
   */
  export interface JWT {
    data: User;
    error: "RefreshTokenExpired" | "RefreshAccessTokenError";
  }
}
