import {
  createContext,
  useContext,
  useEffect,
  useState,
} from "react";

import type {
  ReactNode,
} from "react";

import {
  bootstrapAuthentication,
  login as loginRequest,
  logout as logoutRequest,
  setAuthenticationListener,
} from "../lib/api";

import type {
  AuthUser,
} from "../types/auth";


type AuthContextValue = {
  user: AuthUser | null;

  isBootstrapping: boolean;
  isAuthenticated: boolean;

  login: (
    organizationSlug: string,
    email: string,
    password: string,
  ) => Promise<AuthUser>;

  logout: () => Promise<void>;
};


const AuthContext =
  createContext<
    AuthContextValue | null
  >(
    null,
  );


type AuthProviderProps = {
  children: ReactNode;
};


export function AuthProvider({
  children,
}: AuthProviderProps) {
  const [
    user,
    setUser,
  ] = useState<
    AuthUser | null
  >(
    null,
  );

  const [
    isBootstrapping,
    setIsBootstrapping,
  ] = useState(
    true,
  );


  useEffect(
    () => {
      let active = true;

      setAuthenticationListener(
        (
          nextUser,
        ) => {
          if (active) {
            setUser(
              nextUser,
            );
          }
        },
      );

      void (
        async () => {
          const restoredUser =
            await bootstrapAuthentication();

          if (!active) {
            return;
          }

          setUser(
            restoredUser,
          );

          setIsBootstrapping(
            false,
          );
        }
      )();

      return () => {
        active = false;

        setAuthenticationListener(
          null,
        );
      };
    },
    [],
  );


  async function login(
    organizationSlug: string,
    email: string,
    password: string,
  ): Promise<AuthUser> {
    const result =
      await loginRequest(
        organizationSlug,
        email,
        password,
      );

    setUser(
      result.user,
    );

    return result.user;
  }


  async function logout(
  ): Promise<void> {
    await logoutRequest();

    setUser(
      null,
    );
  }


  return (
    <AuthContext.Provider
      value={{
        user,

        isBootstrapping,

        isAuthenticated:
          user !== null,

        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}


export function useAuth(
): AuthContextValue {
  const context =
    useContext(
      AuthContext,
    );

  if (
    context === null
  ) {
    throw new Error(
      "useAuth must be used "
      + "inside AuthProvider",
    );
  }

  return context;
}