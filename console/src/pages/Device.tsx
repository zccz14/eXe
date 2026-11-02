import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthMini } from "auth-mini-react-components";
import { ArrowLeftIcon, PlayIcon, ShieldAlertIcon, SquareIcon, Trash2Icon } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { api, type CallDetail, type CallView, type DeviceView } from "../api";
import { useAccount } from "../account";
import { newCallId, newNonce, openSealed, signDeviceCall } from "../keystore";
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
  const { id = "" } = useParams();
  const { sdk } = useAuthMini();
  const { account, state: keyState } = useAccount();
  const queryClient = useQueryClient();
  const [tool, setTool] = useState<ToolName>("echo");
  const [argsText, setArgsText] = useState<string>('{"text":"hello eXe"}');
  const [openCall, setOpenCall] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => api<{ devices: DeviceView[] }>(sdk as never, "/api/devices"),
    refetchInterval: 5000,
  });
  const device = devices.data?.devices.find((item) => item.id === id);

  const calls = useQuery({
    queryKey: ["calls", id],
    queryFn: () => api<{ calls: CallView[] }>(sdk as never, `/api/calls?device_id=${id}&limit=50`),
    refetchInterval: 2000,
  });

  const [plaintext, setPlaintext] = useState<unknown>(null);
  const detail = useQuery({
    queryKey: ["call", openCall],
    queryFn: () => api<CallDetail>(sdk as never, `/api/calls/${openCall}`),
    enabled: Boolean(openCall),
    refetchInterval: (query) => (query.state.data?.call.has_result ? false : 2000),
  });

  useEffect(() => {
    const envelope = detail.data?.envelope;
    setPlaintext(null);
    if (!envelope || !detail.data) return;
    let cancelled = false;
    openSealed(detail.data.call.id, detail.data.call.device_id, envelope)
      .then((value) => {
        if (!cancelled) setPlaintext(value);
      })
      .catch((error: Error) => {
        if (!cancelled) setPlaintext({ ok: false, error: error.message });
      });
    return () => {
      cancelled = true;
    };
  }, [detail.data]);

  const send = useMutation({
    mutationFn: async () => {
      if (keyState !== "ready" || !account?.account_id) throw new Error(t("account_missing"));
      let parsed: unknown;
      try {
        parsed = JSON.parse(argsText);
      } catch {
        throw new Error("arguments must be valid JSON");
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("arguments must be a JSON object");
      const issuedAt = Math.floor(Date.now() / 1000);
      const signed = await signDeviceCall({
        callId: newCallId(),
        deviceId: id,
        accountId: account.account_id,
        name: tool,
        args: JSON.stringify(parsed),
        nonce: newNonce(),
        issuedAt,
        expiresAt: issuedAt + 300,
      });
      return api<{ call: CallView }>(sdk as never, `/api/devices/${id}/calls`, {
        method: "POST",
        body: JSON.stringify(signed),
      });
    },
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["calls", id] });
    },
    onError: (value: Error) => setError(value.message),
  });

  const cancel = useMutation({
    mutationFn: (callId: string) => api<void>(sdk as never, `/api/calls/${callId}/cancel`, { method: "POST" }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["calls", id] }),
  });

  const revoke = useMutation({
    mutationFn: () => api<void>(sdk as never, `/api/devices/${id}`, { method: "DELETE" }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["devices"] }),
  });

  if (!device) {
    return <div className="p-6 text-sm text-muted-foreground">{devices.isLoading ? "…" : t("no_devices")}</div>;
  }

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
      <Link to="/devices" className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeftIcon className="size-4" />
        {t("devices_title")}
      </Link>

      <Card className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">{device.label}</h1>
            <p className="text-sm text-muted-foreground">
              {device.hostname} · {device.platform} {device.version ?? ""}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {device.status === "revoked" ? (
              <Badge tone="bad">{t("revoked")}</Badge>
            ) : device.online ? (
              <Badge tone="ok">{t("online")}</Badge>
            ) : (
              <Badge tone="muted">{t("offline")}</Badge>
            )}
            <Button variant="outline" onClick={() => revoke.mutate()} disabled={device.status === "revoked" || revoke.isPending}>
              <Trash2Icon className="size-4" />
              {t("revoke")}
            </Button>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Stat label={t("sas")} value={<span className="font-mono tracking-widest">{device.sas}</span>} />
          <Stat label={t("last_seen")} value={device.last_seen_at ? new Date(device.last_seen_at * 1000).toLocaleString() : "—"} />
          <Stat label={t("device_key")} value={device.sig_pub} mono />
          <Stat label={t("signer")} value={device.kex_pub} mono />
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
          <Button onClick={() => send.mutate()} disabled={send.isPending || device.status === "revoked" || keyState !== "ready"}>
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
            <div key={call.id} className="space-y-2 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <button className="flex items-center gap-2 text-left text-sm" onClick={() => setOpenCall(openCall === call.id ? null : call.id)}>
                  <span className="font-mono text-xs text-muted-foreground">{call.id.slice(0, 8)}</span>
                  <span className="font-medium">{call.name}</span>
                  <Badge tone={statusTone(call.status)}>{t(statusCopy[call.status])}</Badge>
                </button>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>{new Date(call.issued_at * 1000).toLocaleTimeString()}</span>
                  {["queued", "delivered", "received"].includes(call.status) && (
                    <Button variant="ghost" onClick={() => cancel.mutate(call.id)}>
                      <SquareIcon className="size-3.5" />
                      {t("cancel")}
                    </Button>
                  )}
                </div>
              </div>
              {openCall === call.id && (
                <div className="space-y-2 rounded-lg bg-muted/50 p-3 text-xs">
                  <div className="font-mono break-all">{call.args}</div>
                  {detail.isLoading && <div className="text-muted-foreground">…</div>}
                  {plaintext !== null && <pre className="overflow-x-auto font-mono text-xs">{JSON.stringify(plaintext, null, 2)}</pre>}
                  {call.failure_code && <div className="text-destructive">{call.failure_code}</div>}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
