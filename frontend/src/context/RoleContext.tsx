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
  createContext<RoleContextValue | null>(
    null,
  );


type RoleProviderProps = {
  children: ReactNode;
};


export function RoleProvider({
  children,
}: RoleProviderProps) {
  const [role, setRole] =
    useState<UserRole>("staff");

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


export function useRole(): RoleContextValue {
  const context =
    useContext(RoleContext);

  if (context === null) {
    throw new Error(
      "useRole must be used inside RoleProvider",
    );
  }

  return context;
}