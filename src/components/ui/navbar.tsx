"use client";

import { useSession, signIn, signOut } from "next-auth/react";
import { AuthenticationStatus } from "@/lib/constants";

import {
  navigationMenuTriggerStyle,
  NavigationMenu,
  NavigationMenuItem,
  NavigationMenuLink,
  NavigationMenuList
} from "@/components/ui/navigation-menu";

export default function NavigationBar() {
  const { data: _, status } = useSession();
  return (
    <NavigationMenu className={"m-8 space-x-4 justify-end"}>
      <NavigationMenuList className={"justify-end"}>
        <NavigationMenuItem
          hidden={!(status === AuthenticationStatus.UNAUTHENTICATED)}
          onClick={() => signIn()}
        >
          <NavigationMenuLink className={navigationMenuTriggerStyle()}>
            Login
          </NavigationMenuLink>
        </NavigationMenuItem>
        <NavigationMenuItem
          hidden={!(status === AuthenticationStatus.AUTHENTICATED)}
          onClick={() => signOut()}
        >
          <NavigationMenuLink className={navigationMenuTriggerStyle()}>
            Logout
          </NavigationMenuLink>
        </NavigationMenuItem>
      </NavigationMenuList>
    </NavigationMenu>
  );
}
