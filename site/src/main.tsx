import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "lenis/dist/lenis.css";
import "./style.css";
import { Layout } from "./components/Layout";
import { Home } from "./pages/Home";
import { Demo } from "./pages/Demo";
import { Downloads } from "./pages/Downloads";
import { NotFound } from "./pages/NotFound";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="demo" element={<Demo />} />
          <Route path="downloads/:platform?" element={<Downloads />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
