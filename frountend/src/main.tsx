import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "@/components/theme-provider";
import ThreatIntelligenceDashboard from "@/src/pages/Dashboard";
import AdminPage from "@/src/pages/Admin";
import AdminLayout from "@/src/layouts/AdminLayout";
import "@/app/globals.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider defaultTheme="system">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<ThreatIntelligenceDashboard />} />
          <Route
            path="/admin"
            element={
              <AdminLayout>
                <AdminPage />
              </AdminLayout>
            }
          />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  </React.StrictMode>
);
