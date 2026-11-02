import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthMiniProvider } from "auth-mini-react-components";
import { LinkitProvider } from "linkit-react-components";
import { AppLayout } from "@zccz14/ux";
import { LanguagesIcon, MonitorIcon } from "lucide-react";
import "./styles.css";
import { AccountProvider, holdsAccountKey, useAccount } from "./account";
import { LanguageProvider, useCopy, useLang } from "./i18n";
import { ExeMark } from "./mark";
import { DevicePage } from "./pages/Device";
import { DevicesPage } from "./pages/Devices";
import { Button } from "./ui";

// The shared shell renders Linkit widgets, so the console asks AuthMini for those
// audiences too; the worker still only accepts tokens that carry its own audience.
// AuthMini also requires the callback hostname itself, which is this page's origin:
// without it the login page rejects the request outright.
const AUDIENCES = [
  ...new Set([
    ...(import.meta.env.VITE_AUTH_AUDIENCES ?? "exe.ntnl.io,linkit.ntnl.io")
      .split(",")
      .map((value: string) => value.trim())
      .filter(Boolean),
    window.location.hostname,
  ]),
].sort();

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

function KeyBanner() {
  const t = useCopy();
  const { account, state, error } = useAccount();
  const [holds, setHolds] = useState<boolean | null>(null);
  useEffect(() => {
    if (state === "ready" || state === "mismatch") void holdsAccountKey(account).then(setHolds);
  }, [state, account]);
  if (state === "error") return <div className="m-6 rounded-lg border border-destructive/40 p-4 text-sm text-destructive">{error}</div>;
  if (state === "mismatch" || holds === false) {
    return (
      <div className="m-6 rounded-lg border border-amber-500/40 bg-amber-500/5 p-4 text-sm">
        <div className="font-medium">{t("key_missing_title")}</div>
        <p className="mt-1 text-muted-foreground">{t("key_missing_body")}</p>
      </div>
    );
  }
  return null;
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
          items: [{ to: "/devices", label: t("nav_devices"), icon: <MonitorIcon /> }],
        },
      ]}
      headerSlot={
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">v{__APP_VERSION__}</span>
          <LanguageSwitch />
        </div>
      }
    >
      <KeyBanner />
      <Routes>
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:address" element={<DevicePage />} />
        <Route path="*" element={<Navigate replace to="/devices" />} />
      </Routes>
    </AppLayout>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthMiniProvider authMiniBaseUrl="https://auth.ntnl.io" audiences={AUDIENCES} autoRedirectToLogin>
      <LinkitProvider linkitBaseUrl="https://linkit.ntnl.io" lang="zh-CN">
        <QueryClientProvider client={queryClient}>
          <LanguageProvider>
            <AccountProvider>
              <HashRouter>
                <Shell />
              </HashRouter>
            </AccountProvider>
          </LanguageProvider>
        </QueryClientProvider>
      </LinkitProvider>
    </AuthMiniProvider>
  </StrictMode>,
);
