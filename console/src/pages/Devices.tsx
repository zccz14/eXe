import { useQuery } from "@tanstack/react-query";
import { useAuthMini } from "auth-mini-react-components";
import { ChevronRightIcon, TerminalIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api, type DeviceView } from "../api";
import { useCopy } from "../i18n";
import { Badge, Card, Stat } from "../ui";

export function DevicesPage() {
  const t = useCopy();
  const navigate = useNavigate();
  const { sdk } = useAuthMini();
  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => api<{ devices: DeviceView[] }>(sdk as never, "/api/devices"),
    refetchInterval: 5000,
  });
  const list = devices.data?.devices ?? [];

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6 p-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">{t("devices_title")}</h1>
        <p className="text-sm text-muted-foreground">{t("devices_intro")}</p>
      </header>

      <Card className="space-y-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <TerminalIcon className="size-4" />
          {t("connect_title")}
        </div>
        <p className="text-sm text-muted-foreground">{t("connect_body")}</p>
        <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs">exe run</pre>
        <div>
          <button className="text-sm underline underline-offset-4" onClick={() => navigate("/pair")}>
            {t("pair_action")}
          </button>
        </div>
      </Card>

      {list.length === 0 && <div className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground">{t("no_devices")}</div>}

      <div className="grid gap-3 sm:grid-cols-2">
        {list.map((device) => (
          <Card
            key={device.id}
            className="cursor-pointer space-y-3 transition hover:border-foreground/30"
            {...{ onClick: () => navigate(`/devices/${device.id}`) }}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate font-medium">{device.label}</div>
                <div className="truncate text-xs text-muted-foreground">{device.platform}</div>
              </div>
              <ChevronRightIcon className="size-4 shrink-0 text-muted-foreground" />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {device.status === "revoked" ? (
                <Badge tone="bad">{t("revoked")}</Badge>
              ) : device.online ? (
                <Badge tone="ok">{t("online")}</Badge>
              ) : (
                <Badge tone="muted">{t("offline")}</Badge>
              )}
              <Badge>{t("sas")} {device.sas}</Badge>
            </div>
            <Stat label={t("last_seen")} value={device.last_seen_at ? new Date(device.last_seen_at * 1000).toLocaleString() : "—"} />
          </Card>
        ))}
      </div>
    </div>
  );
}
