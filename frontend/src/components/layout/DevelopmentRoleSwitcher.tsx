import {
  useRole,
} from "../../context/RoleContext";

import type {
  UserRole,
} from "../../types/urlAnalysis";


export function DevelopmentRoleSwitcher() {
  const {
    role,
    setRole,
  } = useRole();

  return (
    <div className="role-switcher">
      <label htmlFor="role">
        Rôle simulé
      </label>

      <select
        id="role"
        value={role}
        onChange={(event) => {
          setRole(
            event.target.value as UserRole,
          );
        }}
      >
        <option value="staff">
          Staff
        </option>

        <option value="security_responsible">
          Responsable sécurité
        </option>
      </select>
    </div>
  );
}