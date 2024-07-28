import { withAuth } from "next-auth/middleware";
import { getToken } from "next-auth/jwt";
import { NextResponse } from "next/server";

export default withAuth(
  async function middleware(req) {
    const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
    const baseUrl = req.nextUrl.origin;

    // Check if the user is authenticated
    if (token && Date.now() >= token.data.validity.refresh_until * 1000) {
      // Redirect to the login page
      const response = NextResponse.redirect(`${baseUrl}/api/auth/signin`);
      // Clear the session cookies
      response.cookies.set("next-auth.session-token", "", { maxAge: 0 });
      response.cookies.set("next-auth.csrf-token", "", { maxAge: 0 });

      return response;
    }

    // If authenticated, continue with the request
    return NextResponse.next();
  },
  {
    callbacks: {
      authorized: ({ token }) => {
        // You can add custom logic here, for example, check roles
        return !!token; // if token exists, the user is authenticated
      }
    }
  }
);

// Authenticate all routes except for /api, /_next/static, /_next/image, and .png files
export const config = {
  matcher: ["/((?!api|_next/static|_next/image|.*\\.png$).*)"]
};
