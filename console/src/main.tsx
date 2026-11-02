import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthMiniProvider } from "auth-mini-react-components";
import { LinkitProvider } from "linkit-react-components";
import { AppLayout } from "@zccz14/ux";
import { KeyRoundIcon, LanguagesIcon, MonitorIcon } from "lucide-react";
import "./styles.css";
import { LanguageProvider, useCopy, useLang } from "./i18n";
import { ExeMark } from "./mark";
import { DevicePage } from "./pages/Device";
import { DevicesPage } from "./pages/Devices";
import { PairPage } from "./pages/Pair";
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

function Shell() {
  const t = useCopy();
  return (
    <AppLayout
      logo={<ExeMark />}
      title="eXe"
      nav={[
        {
          label: t("nav_devices"),
          items: [
            { to: "/devices", label: t("nav_devices"), icon: <MonitorIcon /> },
            { to: "/pair", label: t("nav_pair"), icon: <KeyRoundIcon /> },
          ],
        },
      ]}
      headerSlot={<LanguageSwitch />}
    >
      <Routes>
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:id" element={<DevicePage />} />
        <Route path="/pair" element={<PairPage />} />
        <Route path="*" element={<Navigate replace to="/devices" />} />
      </Routes>
    </AppLayout>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthMiniProvider authMiniBaseUrl="https://auth.ntnl.io" audiences={["exe.ntnl.io"]} autoRedirectToLogin>
      <LinkitProvider linkitBaseUrl="https://linkit.ntnl.io" lang="zh-CN">
        <QueryClientProvider client={queryClient}>
          <LanguageProvider>
            <HashRouter>
              <Shell />
            </HashRouter>
          </LanguageProvider>
        </QueryClientProvider>
      </LinkitProvider>
    </AuthMiniProvider>
  </StrictMode>,
);
