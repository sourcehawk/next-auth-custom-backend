import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { login, refresh } from "@/actions/user-auth";
import type {
  AuthOptions,
  User,
  UserObject,
  AuthValidity,
  BackendAccessJWT,
  BackendJWT,
  DecodedJWT
} from "next-auth";
import type { JWT } from "next-auth/jwt";
import { jwtDecode } from "jwt-decode";

async function refreshAccessToken(nextAuthJWT: JWT): Promise<JWT> {
  try {
    // Get a new access token from backend using the refresh token
    const res = await refresh(nextAuthJWT.data.tokens.refresh);
    const accessToken: BackendAccessJWT = await res.json();

    if (!res.ok) throw accessToken;
    const { exp }: DecodedJWT = jwtDecode(accessToken.access);

    // Update the token and validity in the next-auth object
    nextAuthJWT.data.validity.valid_until = exp;
    nextAuthJWT.data.tokens.access = accessToken.access;

    return { ...nextAuthJWT };
  } catch (error) {
    console.debug(error);
    return {
      ...nextAuthJWT,
      error: "RefreshAccessTokenError"
    };
  }
}

export const authOptions: AuthOptions = {
  secret: process.env.NEXTAUTH_SECRET,
  session: { strategy: "jwt" },
  providers: [
    CredentialsProvider({
      name: "Login",
      credentials: {
        email: {
          label: "Email",
          type: "email",
          placeholder: "john@mail.com"
        },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        try {
          const res = await login(
            credentials?.email || "",
            credentials?.password || ""
          );
          const tokens: BackendJWT = await res.json();
          if (!res.ok) throw tokens;

          const access: DecodedJWT = jwtDecode(tokens.access);
          const refresh: DecodedJWT = jwtDecode(tokens.refresh);
          // Extract the user from the access token
          const user: UserObject = {
            name: access.name,
            email: access.email,
            id: access.id
          };
          // Extract the auth validity from the tokens
          const validity: AuthValidity = {
            valid_until: access.exp,
            refresh_until: refresh.exp
          };
          // Return the object that next-auth calls 'User' (which we've defined in next-auth.d.ts)
          return {
            id: refresh.jti, // User object is forced to have a string id so use refresh token id
            tokens: tokens,
            user: user,
            validity: validity
          } as User;
        } catch (error) {
          console.error(error);
          return null;
        }
      }
    })
  ],
  callbacks: {
    async redirect({ url, baseUrl }) {
      return url.startsWith(baseUrl)
        ? Promise.resolve(url)
        : Promise.resolve(baseUrl);
    },
    async jwt({ token, user, account }) {
      // Initial signin contains a 'User' object from authorize method
      if (user && account) {
        console.debug("Initial signin");
        return { ...token, data: user };
      }

      // The current access token is still valid
      if (Date.now() < token.data.validity.valid_until * 1000) {
        console.debug("Access token is still valid");
        return token;
      }

      // The current access token has expired, but the refresh token is still valid
      if (Date.now() < token.data.validity.refresh_until * 1000) {
        console.debug("Access token is being refreshed");
        return await refreshAccessToken(token);
      }

      // The current access token and refresh token have both expired
      // This should not really happen unless you get really unlucky with
      // the timing of the token expiration because the middleware should
      // have caught this case before the callback is called
      console.debug("Both tokens have expired");
      return { ...token, error: "RefreshTokenExpired" } as JWT;
    },
    async session({ session, token, user }) {
      session.user = token.data.user;
      session.validity = token.data.validity;
      session.error = token.error;
      return session;
    }
  }
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
