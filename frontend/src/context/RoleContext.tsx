import {
  createContext,
  useContext,
  useState,
} from "react";

import type {
  ReactNode,
} from "react";

import type {
  UserRole,
} from "../types/urlAnalysis";


type RoleContextValue = {
  role: UserRole;

  setRole: (
    role: UserRole,
  ) => void;
};


const RoleContext =
  createContext<
    RoleContextValue | null
  >(
    null,
  );


const ROLE_STORAGE_KEY =
  "tip-dev-role";


function isUserRole(
  value: string | null,
): value is UserRole {
  return (
    value === "staff"
    || value
      === "security_responsible"
  );
}


function getInitialRole(
): UserRole {
  const storedRole =
    window.localStorage.getItem(
      ROLE_STORAGE_KEY,
    );

  if (
    isUserRole(
      storedRole,
    )
  ) {
    return storedRole;
  }

  return "staff";
}


type RoleProviderProps = {
  children: ReactNode;
};


export function RoleProvider({
  children,
}: RoleProviderProps) {
  const [
    role,
    setStoredRole,
  ] = useState<UserRole>(
    getInitialRole,
  );


  function setRole(
    nextRole: UserRole,
  ) {
    window.localStorage.setItem(
      ROLE_STORAGE_KEY,
      nextRole,
    );

    setStoredRole(
      nextRole,
    );
  }


  return (
    <RoleContext.Provider
      value={{
        role,
        setRole,
      }}
    >
      {children}
    </RoleContext.Provider>
  );
}


export function useRole(
): RoleContextValue {
  const context =
    useContext(
      RoleContext,
    );

  if (
    context === null
  ) {
    throw new Error(
      "useRole must be used inside RoleProvider",
    );
  }

  return context;
}