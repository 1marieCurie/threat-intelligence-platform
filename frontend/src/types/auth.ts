export type UserRole =
  | "staff"
  | "security_responsible";


export type AuthUser = {
  user_id: string;
  organization_id: string;

  email: string;
  display_name: string;

  role: UserRole;
};


export type AuthTokenResponse = {
  access_token: string;
  token_type: "bearer";
  expires_in: number;

  user: AuthUser;
};