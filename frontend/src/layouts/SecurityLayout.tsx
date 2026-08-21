import {
  NavLink,
  Outlet,
} from "react-router";

import {
  DevelopmentRoleSwitcher,
} from "../components/layout/DevelopmentRoleSwitcher";


type NavigationItem = {
  label: string;
  path: string;
};


const navigationItems: NavigationItem[] = [
  {
    label: "Dashboard",
    path: "/dashboard",
  },
  {
    label: "Machines",
    path: "/machines",
  },
  {
    label: "Inventaires",
    path: "/inventaires",
  },
  {
    label: "Logiciels",
    path: "/logiciels",
  },
  {
    label: "Vulnérabilités",
    path: "/vulnerabilites",
  },
  {
    label: "Alertes",
    path: "/alertes",
  },
  {
    label: "Analyse URL",
    path: "/analyse-url",
  },
];


export function SecurityLayout() {
  return (
    <div className="security-shell">
      <aside className="security-sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">
            TI
          </div>

          <div className="sidebar-brand__text">
            <strong>
              Threat Intelligence
            </strong>

            <span>
              Security Console
            </span>
          </div>
        </div>

        <div className="sidebar-section-label">
          Navigation
        </div>

        <nav
          className="security-nav"
          aria-label="Navigation principale"
        >
          {navigationItems.map(
            (item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({
                  isActive,
                }) =>
                  isActive
                    ? (
                      "security-nav-link "
                      + "security-nav-link--active"
                    )
                    : "security-nav-link"
                }
              >
                {item.label}
              </NavLink>
            ),
          )}
        </nav>

        <div className="sidebar-footer">
          <span>
            Mode développement
          </span>

          <strong>
            security_responsible
          </strong>
        </div>
      </aside>

      <div className="security-main">
        <header className="security-topbar">
          <div className="security-topbar__context">
            <span className="security-topbar__eyebrow">
              Espace sécurité
            </span>

            <strong className="security-topbar__title">
              Supervision
            </strong>
          </div>

          <DevelopmentRoleSwitcher />
        </header>

        <div className="security-content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}