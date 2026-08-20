import {
  Navigate,
  Route,
  Routes,
} from "react-router";

import {
  useRole,
} from "./context/RoleContext";

import {
  AlertsPage,
} from "./features/alerts/AlertsPage";

import {
  DashboardPage,
} from "./features/dashboard/DashboardPage";

import {
  InventoryPage,
} from "./features/inventory/InventoryPage";

import {
  MachineDetailPage,
} from "./features/machines/MachineDetailPage";

import {
  MachinesPage,
} from "./features/machines/MachinesPage";

import {
  SoftwarePage,
} from "./features/software/SoftwarePage";

import {
  URLAnalysisPage,
} from "./features/url-analysis/URLAnalysisPage";

import {
  VulnerabilityDetailPage,
} from "./features/vulnerabilities/VulnerabilityDetailPage";

import {
  VulnerabilitiesPage,
} from "./features/vulnerabilities/VulnerabilitiesPage";

import {
  SecurityLayout,
} from "./layouts/SecurityLayout";

import {
  StaffLayout,
} from "./layouts/StaffLayout";


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
            <MachinesPage />
          }
        />

        <Route
          path="machines/:machineId"
          element={
            <MachineDetailPage />
          }
        />

        <Route
          path="inventaires"
          element={
            <InventoryPage />
          }
        />

        <Route
          path="logiciels"
          element={
            <SoftwarePage />
          }
        />

        <Route
          path="vulnerabilites"
          element={
            <VulnerabilitiesPage />
          }
        />

        <Route
          path="vulnerabilites/:vulnerabilityId"
          element={
            <VulnerabilityDetailPage />
          }
        />

        <Route
          path="alertes"
          element={
            <AlertsPage />
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