import {
  Outlet,
} from "react-router";

import {
  Button,
} from "../components/ui/Button";

import {
  useAuth,
} from "../context/AuthContext";


export function StaffLayout() {
  const {
    user,
    logout,
  } = useAuth();


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

        <div className="auth-user-actions">
          <div className="auth-user-summary">
            <strong>
              {user?.display_name}
            </strong>

            <span>
              {user?.email}
            </span>
          </div>

          <Button
            type="button"
            onClick={() => {
              void logout();
            }}
          >
            Déconnexion
          </Button>
        </div>
      </header>

      <Outlet />
    </div>
  );
}