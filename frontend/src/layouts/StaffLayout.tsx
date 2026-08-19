import {
  Outlet,
} from "react-router";

import {
  DevelopmentRoleSwitcher,
} from "../components/layout/DevelopmentRoleSwitcher";

import {
  useRole,
} from "../context/RoleContext";


export function StaffLayout() {
  const {
    role,
  } = useRole();

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            TI
          </div>

          <div>
            <strong>
              Threat Intelligence
            </strong>

            <span>
              Platform
            </span>
          </div>
        </div>

        <DevelopmentRoleSwitcher />
      </header>

      <div className="development-banner">
        Mode développement
        <span>·</span>
        <strong>
          {role}
        </strong>
      </div>

      <Outlet />
    </div>
  );
}