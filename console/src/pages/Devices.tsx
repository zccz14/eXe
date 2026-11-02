import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthMini } from "auth-mini-react-components";
import { ChevronRightIcon, PlusIcon, TerminalIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api, type DeviceView } from "../api";
import { DownloadCard } from "../components/DownloadCard";
import { useCopy } from "../i18n";
import { Badge, Button, Card, Input, Stat } from "../ui";

export function DevicesPage() {
  const t = useCopy();
  const navigate = useNavigate();
  const { sdk } = useAuthMini();
  const queryClient = useQueryClient();
  const [address, setAddress] = useState("");
  const [label, setLabel] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => api<{ devices: DeviceView[] }>(sdk as never, "/api/devices"),
    refetchInterval: 5000,
  });
  const list = devices.data?.devices ?? [];

  const add = useMutation({
    mutationFn: () =>
      api<{ device: DeviceView }>(sdk as never, "/api/devices", {
        method: "POST",
        body: JSON.stringify({ address: address.trim(), label: label.trim() || undefined }),
      }),
    onSuccess: () => {
      setAddress("");
      setLabel("");
      setNotice(null);
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (error: Error) => setNotice(error.message),
  });

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6 p-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">{t("devices_title")}</h1>
        <p className="text-sm text-muted-foreground">{t("devices_intro")}</p>
      </header>

      <DownloadCard />

      <Card className="space-y-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <PlusIcon className="size-4" />
          {t("add_title")}
        </div>
        <p className="text-sm text-muted-foreground">{t("add_body")}</p>
        <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs">exe run</pre>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder={t("device_address")}
            className="font-mono text-xs"
            aria-label={t("device_address")}
          />
          <Input value={label} onChange={(event) => setLabel(event.target.value)} placeholder={t("label_device")} />
          <Button onClick={() => add.mutate()} disabled={add.isPending || address.trim().length < 32}>
            <TerminalIcon className="size-4" />
            {t("add_device")}
          </Button>
        </div>
        {notice && <p className="text-sm text-destructive">{notice}</p>}
      </Card>

      {list.length === 0 && <div className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground">{t("no_devices")}</div>}

      <div className="grid gap-3 sm:grid-cols-2">
        {list.map((device) => (
          <Card
            key={device.address}
            className="cursor-pointer space-y-3 transition hover:border-foreground/30"
            {...{ onClick: () => navigate(`/devices/${device.address}`) }}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate font-medium">{device.label}</div>
                <div className="truncate font-mono text-xs text-muted-foreground">{device.address}</div>
              </div>
              <ChevronRightIcon className="size-4 shrink-0 text-muted-foreground" />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {device.revoked_at ? (
                <Badge tone="bad">{t("revoked")}</Badge>
              ) : device.online ? (
                <Badge tone="ok">{t("online")}</Badge>
              ) : (
                <Badge tone="muted">{t("offline")}</Badge>
              )}
              {device.platform && <Badge>{device.platform}</Badge>}
            </div>
            <Stat label={t("last_seen")} value={device.last_seen_at ? new Date(device.last_seen_at * 1000).toLocaleString() : "—"} />
          </Card>
        ))}
      </div>
    </div>
  );
}
