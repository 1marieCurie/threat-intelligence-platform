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