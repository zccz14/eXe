import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeftIcon, PlayIcon, ShieldAlertIcon, SquareIcon, Trash2Icon } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { api, type CallDetail, type CallView, type DeviceView } from "../api";
import { localCalls, newCallId, openSealed, sealDeviceCall } from "../keystore";
import { statusCopy, useCopy } from "../i18n";
import { Badge, Button, Card, Input, Stat } from "../ui";

const TOOLS = [
  { name: "echo", hint: '{"text":"hello eXe"}' },
  { name: "sysinfo", hint: "{}" },
  { name: "sleep", hint: '{"seconds":5}' },
  { name: "bash", hint: '{"command":"uname -a"}' },
] as const;

type ToolName = (typeof TOOLS)[number]["name"];

function statusTone(status: CallView["status"]): "muted" | "ok" | "warn" | "bad" {
  if (status === "succeeded") return "ok";
  if (status === "failed") return "bad";
  if (status === "queued" || status === "delivered" || status === "received") return "warn";
  return "muted";
}

export function DevicePage() {
  const t = useCopy();
  const { address = "" } = useParams();
  const queryClient = useQueryClient();
  const [tool, setTool] = useState<ToolName>("echo");
  const [argsText, setArgsText] = useState<string>('{"text":"hello eXe"}');
  const [openCall, setOpenCall] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => api<{ devices: DeviceView[] }>("/api/devices"),
    refetchInterval: 5000,
  });
  const device = devices.data?.devices.find((item) => item.address === address);

  const calls = useQuery({
    queryKey: ["calls", address],
    queryFn: () => api<{ calls: CallView[] }>(`/api/calls?device=${address}&limit=50`),
    refetchInterval: 2000,
  });

  const [plaintext, setPlaintext] = useState<unknown>(null);
  const [local, setLocal] = useState<Record<string, { name: string; args: string }>>({});
  const detail = useQuery({
    queryKey: ["call", openCall],
    queryFn: () => api<CallDetail>(`/api/calls/${openCall}`),
    enabled: Boolean(openCall),
    refetchInterval: (query) => (query.state.data?.call.has_result ? false : 2000),
  });

  useEffect(() => {
    void localCalls().then(setLocal);
  }, [calls.data]);

  useEffect(() => {
    setPlaintext(null);
    if (!detail.data?.result) return;
    let cancelled = false;
    openSealed({ call: detail.data.call, result: detail.data.result })
      .then((value) => {
        if (!cancelled) setPlaintext(value);
      })
      .catch((openError: Error) => {
        if (!cancelled) setPlaintext({ ok: false, error: openError.message });
      });
    return () => {
      cancelled = true;
    };
  }, [detail.data]);

  const send = useMutation({
    mutationFn: async () => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(argsText);
      } catch {
        throw new Error("arguments must be valid JSON");
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("arguments must be a JSON object");
      const call = await sealDeviceCall({
        callId: newCallId(),
        device: address,
        name: tool,
        args: JSON.stringify(parsed),
      });
      return api<{ call: CallView }>(`/api/devices/${address}/calls`, {
        method: "POST",
        body: JSON.stringify(call),
      });
    },
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["calls", address] });
      void localCalls().then(setLocal);
    },
    onError: (value: Error) => setError(value.message),
  });

  const cancel = useMutation({
    mutationFn: (callId: string) => api<void>(`/api/calls/${callId}/cancel`, { method: "POST" }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["calls", address] }),
  });

  const remove = useMutation({
    mutationFn: () => api<void>(`/api/devices/${address}`, { method: "DELETE" }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["devices"] }),
  });

  if (!device) {
    return <div className="p-6 text-sm text-muted-foreground">{devices.isLoading ? "…" : t("no_devices")}</div>;
  }

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6 p-6">
      <Link to="/devices" className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeftIcon className="size-4" />
        {t("devices_title")}
      </Link>

      <Card className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">{device.label}</h1>
            <p className="font-mono text-xs text-muted-foreground">{device.address}</p>
            <p className="text-sm text-muted-foreground">
              {[device.hostname, device.platform, device.version].filter(Boolean).join(" · ") || t("never_seen")}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {device.online ? <Badge tone="ok">{t("online")}</Badge> : <Badge tone="muted">{t("offline")}</Badge>}
            <Button variant="outline" onClick={() => remove.mutate()} disabled={remove.isPending}>
              <Trash2Icon className="size-4" />
              {t("remove_device")}
            </Button>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Stat label={t("last_seen")} value={device.last_seen_at ? new Date(device.last_seen_at * 1000).toLocaleString() : "—"} />
          <Stat label={t("device_address")} value={device.address} mono />
        </div>
      </Card>

      <Card className="space-y-3">
        <div className="text-sm font-medium">{t("send_call")}</div>
        <div className="flex flex-wrap gap-2">
          {TOOLS.map((item) => (
            <Button
              key={item.name}
              variant={tool === item.name ? "default" : "outline"}
              onClick={() => {
                setTool(item.name);
                setArgsText(item.hint);
              }}
            >
              {item.name}
            </Button>
          ))}
        </div>
        <Input className="font-mono text-xs" value={argsText} onChange={(event) => setArgsText(event.target.value)} aria-label={t("arguments")} />
        <div className="flex items-center justify-between gap-3">
          <p className="flex items-center gap-1 text-xs text-muted-foreground">
            <ShieldAlertIcon className="size-3.5" />
            {t("policy_note")}
          </p>
          <Button onClick={() => send.mutate()} disabled={send.isPending}>
            <PlayIcon className="size-4" />
            {t("run")}
          </Button>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
      </Card>

      <section className="space-y-3">
        <h2 className="text-sm font-medium">{t("calls")}</h2>
        {(calls.data?.calls.length ?? 0) === 0 && <p className="text-sm text-muted-foreground">{t("no_calls")}</p>}
        <div className="divide-y divide-border rounded-xl border border-border">
          {(calls.data?.calls ?? []).map((call) => (
            <div key={call.call_id} className="space-y-2 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <button className="flex items-center gap-2 text-left text-sm" onClick={() => setOpenCall(openCall === call.call_id ? null : call.call_id)}>
                  <span className="font-mono text-xs text-muted-foreground">{call.call_id.slice(0, 8)}</span>
                  <span className="font-medium">{local[call.call_id]?.name ?? t("sealed_call")}</span>
                  <Badge tone={statusTone(call.status)}>{t(statusCopy[call.status])}</Badge>
                </button>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>{new Date(call.issued_at * 1000).toLocaleTimeString()}</span>
                  {["queued", "delivered", "received"].includes(call.status) && (
                    <Button variant="ghost" onClick={() => cancel.mutate(call.call_id)}>
                      <SquareIcon className="size-3.5" />
                      {t("cancel")}
                    </Button>
                  )}
                </div>
              </div>
              {openCall === call.call_id && (
                <div className="space-y-2 rounded-lg bg-muted/50 p-3 text-xs">
                  <div className="font-mono break-all">{local[call.call_id]?.args ?? "—"}</div>
                  {detail.isLoading && <div className="text-muted-foreground">…</div>}
                  {plaintext !== null && <pre className="overflow-x-auto font-mono text-xs">{JSON.stringify(plaintext, null, 2)}</pre>}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
