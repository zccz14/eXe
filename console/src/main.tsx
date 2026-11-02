import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter, Link, Navigate, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LanguagesIcon } from "lucide-react";
import "./styles.css";
import { LanguageProvider, useCopy, useLang } from "./i18n";
import { ExeMark } from "./mark";
import { DevicePage } from "./pages/Device";
import { DevicesPage } from "./pages/Devices";
import { Button } from "./ui";

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 0, refetchOnWindowFocus: false } } });

function LanguageSwitch() {
  const { lang, setLang } = useLang();
  const t = useCopy();
  return (
    <Button variant="ghost" title={t("language")} onClick={() => setLang(lang === "zh" ? "en" : "zh")}>
      <LanguagesIcon className="size-4" />
      <span className="text-xs uppercase">{lang}</span>
    </Button>
  );
}

/**
 * There is nothing to log in to: this page is a static shell plus one key in this
 * browser, so the header only carries the version and the language.
 */
function Shell() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-10 border-b border-border bg-background/85 backdrop-blur">
        <div className="mx-auto flex w-full max-w-5xl items-center gap-2 px-6 py-3">
          <Link to="/devices" className="flex items-center gap-2">
            <ExeMark />
            <span className="text-base font-semibold">eXe</span>
          </Link>
          <span className="text-xs text-muted-foreground">v{__APP_VERSION__}</span>
          <div className="ml-auto">
            <LanguageSwitch />
          </div>
        </div>
      </header>
      <main className="flex-1">
        <Routes>
          <Route path="/devices" element={<DevicesPage />} />
          <Route path="/devices/:address" element={<DevicePage />} />
          <Route path="*" element={<Navigate replace to="/devices" />} />
        </Routes>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <LanguageProvider>
        <HashRouter>
          <Shell />
        </HashRouter>
      </LanguageProvider>
    </QueryClientProvider>
  </StrictMode>,
);
