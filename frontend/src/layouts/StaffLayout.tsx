import {
  NavLink,
  Outlet,
} from "react-router";

import {
  ShieldCheck,
} from "lucide-react";

import {
  Button,
} from "../components/ui/Button";
import {
  useAuth,
} from "../context/AuthContext";

import "./layout-polish.css";


export function StaffLayout() {
  const { user, logout } = useAuth();

  return (
    <div className="app-shell">
      <header className="topbar staff-topbar">
        <div className="brand">
          <div className="brand-mark platform-brand-mark" aria-hidden="true">
            <ShieldCheck size={18} strokeWidth={1.8} />
          </div>

          <div>
            <strong>Threat Intelligence</strong>
            <span>Platform</span>
          </div>
        </div>

        <nav className="staff-nav" aria-label="Navigation staff">
          <NavLink
            to="/analyse-url"
            className={({ isActive }) =>
              isActive
                ? "staff-nav-link staff-nav-link--active"
                : "staff-nav-link"
            }
          >
            Analyse URL
          </NavLink>

          <NavLink
            to="/aide"
            className={({ isActive }) =>
              isActive
                ? "staff-nav-link staff-nav-link--active"
                : "staff-nav-link"
            }
          >
            Centre d'aide
          </NavLink>
        </nav>

        <div className="auth-user-actions">
          <div className="auth-user-summary">
            <strong>{user?.display_name}</strong>
            <span>{user?.email}</span>
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
