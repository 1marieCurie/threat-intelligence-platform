import {
  StrictMode,
} from "react";

import {
  createRoot,
} from "react-dom/client";

import {
  BrowserRouter,
} from "react-router";

import App from "./App";

import {
  AuthProvider,
} from "./context/AuthContext";

import "./index.css";
import "./minimal-theme.css";
import "./auth.css";
import "./final-ui-polish.css";
import "./features/help/security-help.css";
import "./security-console-polish.css";
import "./icon-alignment.css";
import "./security-visual-balance.css";
import "./security-detail-readability.css";
import "./features/dashboard/dashboard-final-polish.css";
import "./final-alignment-fixes.css";


createRoot(
  document.getElementById(
    "root",
  )!,
).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
