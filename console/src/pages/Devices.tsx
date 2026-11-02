import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, ChevronRightIcon, CopyIcon, FingerprintIcon, PlusIcon, TerminalIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { api, type DeviceStatus, type Me } from "../api";
import { bookList, bookPut, looksLikeAddress, type BookEntry } from "../book";
import { DownloadCard } from "../components/DownloadCard";
import { useCopy } from "../i18n";
import { Badge, Button, Card, Input, Stat } from "../ui";

/** The address a device has to trust; it is the only thing this browser is. */
function ConsoleAddressCard() {
  const t = useCopy();
  const [copied, setCopied] = useState(false);
  const me = useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/api/me"), retry: 0 });
  const address = me.data?.address;

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(timer);
  }, [copied]);

  return (
    <Card className="space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        <FingerprintIcon className="size-4" />
        {t("console_address")}
      </div>
      <p className="text-sm text-muted-foreground">{t("console_address_body")}</p>
      {me.isError ? (
        <p className="text-sm text-destructive">{t("relay_unreachable")}</p>
      ) : (
        <>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <code className="min-w-0 flex-1 truncate rounded-md bg-muted px-3 py-2 font-mono text-xs">{address ?? "…"}</code>
            <Button
              variant="outline"
              className="shrink-0"
              disabled={!address}
              onClick={() => {
                if (!address) return;
                void navigator.clipboard.writeText(address).then(() => setCopied(true));
              }}
            >
              {copied ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
              {copied ? t("copied") : t("copy")}
            </Button>
          </div>
          {address && <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs">exe trust {address}</pre>}
        </>
      )}
    </Card>
  );
}

/** The label comes from this browser; the online state comes from the relay, per address. */
function DeviceCard({ entry }: { entry: BookEntry }) {
  const t = useCopy();
  const navigate = useNavigate();
  const status = useQuery({
    queryKey: ["device", entry.address],
    queryFn: () => api<DeviceStatus>(`/api/devices/${entry.address}`),
    refetchInterval: 5000,
  });
  const device = status.data;

  return (
    <Card
      className="cursor-pointer space-y-3 transition hover:border-foreground/30"
      {...{ onClick: () => navigate(`/devices/${entry.address}`) }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-medium">{entry.label}</div>
          <div className="truncate font-mono text-xs text-muted-foreground">{entry.address}</div>
        </div>
        <ChevronRightIcon className="size-4 shrink-0 text-muted-foreground" />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {device?.online ? <Badge tone="ok">{t("online")}</Badge> : <Badge tone="muted">{t("offline")}</Badge>}
        {device?.platform && <Badge>{device.platform}</Badge>}
      </div>
      <Stat label={t("last_seen")} value={device?.last_seen_at ? new Date(device.last_seen_at * 1000).toLocaleString() : "—"} />
    </Card>
  );
}

export function DevicesPage() {
  const t = useCopy();
  const queryClient = useQueryClient();
  const [address, setAddress] = useState("");
  const [label, setLabel] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const book = useQuery({ queryKey: ["book"], queryFn: bookList });
  const entries = book.data ?? [];

  const add = useMutation({
    mutationFn: () => bookPut(address.trim(), label),
    onSuccess: () => {
      setAddress("");
      setLabel("");
      setNotice(null);
      void queryClient.invalidateQueries({ queryKey: ["book"] });
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

      <ConsoleAddressCard />

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
            className="font-mono text-xs sm:min-w-0 sm:flex-[3]"
            aria-label={t("device_address")}
          />
          <Input
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            placeholder={t("label_device")}
            className="sm:min-w-0 sm:flex-[2]"
          />
          <Button
            className="shrink-0 whitespace-nowrap"
            onClick={() => {
              if (!looksLikeAddress(address)) {
                setNotice(t("device_address"));
                return;
              }
              add.mutate();
            }}
            disabled={add.isPending || address.trim().length < 32}
          >
            <TerminalIcon className="size-4" />
            {t("add_device")}
          </Button>
        </div>
        {notice && <p className="text-sm text-destructive">{notice}</p>}
        <p className="text-xs text-muted-foreground">{t("book_note")}</p>
      </Card>

      {entries.length === 0 && (
        <div className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground">{t("no_devices")}</div>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        {entries.map((entry) => (
          <DeviceCard key={entry.address} entry={entry} />
        ))}
      </div>
    </div>
  );
}
