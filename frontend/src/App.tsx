import {
  Navigate,
  Route,
  Routes,
} from "react-router";

import {
  URLAnalysisPage,
} from "./features/url-analysis/URLAnalysisPage";

import {
  StaffLayout,
} from "./layouts/StaffLayout";

import {
  SecurityLayout,
} from "./layouts/SecurityLayout";

import {
  SecurityPlaceholderPage,
} from "./pages/SecurityPlaceholderPage";

import {
  useRole,
} from "./context/RoleContext";

import {
  DashboardPage,
} from "./features/dashboard/DashboardPage";

function StaffRoutes() {
  return (
    <Routes>
      <Route
        element={
          <StaffLayout />
        }
      >
        <Route
          path="analyse-url"
          element={
            <URLAnalysisPage />
          }
        />

        <Route
          path="*"
          element={
            <Navigate
              to="/analyse-url"
              replace
            />
          }
        />
      </Route>
    </Routes>
  );
}


function SecurityRoutes() {
  return (
    <Routes>
      <Route
        element={
          <SecurityLayout />
        }
      >
        <Route
          path="dashboard"
          element={
            <DashboardPage />
          }
        />

        <Route
          path="machines"
          element={
            <SecurityPlaceholderPage
              title="Machines"
              description={
                "Inventaire des machines "
                + "et de leur exposition."
              }
            />
          }
        />

        <Route
          path="logiciels"
          element={
            <SecurityPlaceholderPage
              title="Logiciels"
              description={
                "Composants logiciels détectés "
                + "sur les machines."
              }
            />
          }
        />

        <Route
          path="vulnerabilites"
          element={
            <SecurityPlaceholderPage
              title="Vulnérabilités"
              description={
                "Vue agrégée des vulnérabilités "
                + "affectant l'organisation."
              }
            />
          }
        />

        <Route
          path="alertes"
          element={
            <SecurityPlaceholderPage
              title="Alertes"
              description={
                "Centre opérationnel des "
                + "notifications de sécurité."
              }
            />
          }
        />

        <Route
          path="analyse-url"
          element={
            <URLAnalysisPage />
          }
        />

        <Route
          path="*"
          element={
            <Navigate
              to="/dashboard"
              replace
            />
          }
        />
      </Route>
    </Routes>
  );
}


function App() {
  const {
    role,
  } = useRole();

  if (
    role
    === "security_responsible"
  ) {
    return (
      <SecurityRoutes />
    );
  }

  return (
    <StaffRoutes />
  );
}


export default App;