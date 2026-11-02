import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeftIcon, PlayIcon, ShieldAlertIcon, SquareIcon, Trash2Icon } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, apiBytes, type CallDetail, type CallView, type DeviceStatus } from "../api";
import { bookList, bookRemove } from "../book";
import { localCalls, newCallId, openAttachment, openSealed, rememberResult, sealDeviceCall, type LocalCall } from "../keystore";
import { statusCopy, useCopy } from "../i18n";
import { Badge, Button, Card, Input, Stat } from "../ui";

/** The device has exactly one verb; the name is still a field because the wire carries it. */
const DEFAULT_TOOL = "shell";

/** The size of the attachment a result points at, or null when it is inline. */
function attachmentBytes(value: unknown): number | null {
  if (typeof value !== "object" || value === null) return null;
  const blob = (value as { blob?: unknown }).blob;
  if (typeof blob !== "object" || blob === null) return null;
  const bytes = (blob as { bytes?: unknown }).bytes;
  return typeof bytes === "number" ? bytes : null;
}

function statusTone(status: CallView["status"]): "muted" | "ok" | "warn" | "bad" {
  if (status === "succeeded") return "ok";
  if (status === "failed") return "bad";
  // `lost` is not a failure we witnessed: the process that took the call went
  // away, so nobody knows what happened. It is flagged, not hidden.
  if (status === "lost") return "bad";
  if (status === "queued" || status === "received") return "warn";
  return "muted";
}

export function DevicePage() {
  const t = useCopy();
  const { address = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tool, setTool] = useState(DEFAULT_TOOL);
  const [argsText, setArgsText] = useState<string>('{"command":"uname -a"}');
  const [openCall, setOpenCall] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const book = useQuery({ queryKey: ["book"], queryFn: bookList });
  const entry = book.data?.find((item) => item.address === address);

  const status = useQuery({
    queryKey: ["device", address],
    queryFn: () => api<DeviceStatus>(`/api/devices/${address}`),
    refetchInterval: 5000,
  });
  const device = status.data;

  const calls = useQuery({
    queryKey: ["calls", address],
    queryFn: () => api<{ calls: CallView[] }>(`/api/calls?device=${address}&limit=50`),
    refetchInterval: 2000,
  });

  const [plaintext, setPlaintext] = useState<unknown>(null);
  const [attachment, setAttachment] = useState<unknown>(null);
  const [local, setLocal] = useState<Record<string, LocalCall>>({});
  const detail = useQuery({
    queryKey: ["call", openCall],
    queryFn: () => api<CallDetail>(`/api/calls/${openCall}`),
    enabled: Boolean(openCall),
    refetchInterval: (query) => (query.state.data?.call.has_result ? false : 2000),
  });

  useEffect(() => {
    void localCalls().then(setLocal);
  }, [calls.data]);

  /**
   * Taking the result ends the call's life on the relay. This browser keeps its
   * own copy first, then tells the relay it can forget the row.
   */
  const keep = async (callId: string, value: unknown) => {
    await rememberResult(callId, value);
    await api(`/api/calls/${callId}/ack`, { method: "POST" }).catch(() => undefined);
    void localCalls().then(setLocal);
  };

  useEffect(() => {
    setPlaintext(null);
    setAttachment(null);
    if (!detail.data?.result) return;
    let cancelled = false;
    openSealed({ call: detail.data.call, result: detail.data.result })
      .then((value) => {
        if (cancelled) return;
        setPlaintext(value);
        // A result with an attachment is only half-picked-up; the rest is one
        // click away, so the row waits for that click (or the fallback sweep).
        if (attachmentBytes(value) === null && openCall) void keep(openCall, value);
      })
      .catch((openError: Error) => {
        if (!cancelled) setPlaintext({ ok: false, error: openError.message });
      });
    return () => {
      cancelled = true;
    };
  }, [detail.data]);

  // A result too big for one row arrives as a reference; the bytes are fetched
  // separately and opened with the same key that opens inline results.
  const loadAttachment = useMutation({
    mutationFn: async () => {
      if (!openCall || !detail.data?.result) throw new Error(t("attachment_failed"));
      const bytes = await apiBytes(`/api/calls/${openCall}/blob`);
      return openAttachment(detail.data.call, detail.data.result, bytes);
    },
    onSuccess: (value) => {
      setAttachment(value);
      if (openCall) void keep(openCall, value);
    },
  });

  // Calls the relay has already forgotten because this browser picked them up.
  const relayIds = new Set((calls.data?.calls ?? []).map((call) => call.call_id));
  const archived = Object.values(local).filter((call) => call.result !== undefined && !relayIds.has(call.call_id));

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

  /** Local only: this browser stops listing the address; nothing on the device changes. */
  const forget = useMutation({
    mutationFn: () => bookRemove(address),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["book"] });
      navigate("/devices");
    },
  });

  if (book.isLoading) return <div className="p-6 text-sm text-muted-foreground">…</div>;
  if (!entry) {
    return (
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-4 p-6 text-sm text-muted-foreground">
        <Link to="/devices" className="flex items-center gap-1 hover:text-foreground">
          <ArrowLeftIcon className="size-4" />
          {t("devices_title")}
        </Link>
        <p>{t("not_in_book")}</p>
      </div>
    );
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
            <h1 className="text-xl font-semibold">{entry.label}</h1>
            <p className="font-mono text-xs text-muted-foreground">{entry.address}</p>
            <p className="text-sm text-muted-foreground">
              {[device?.platform, device?.version].filter(Boolean).join(" · ") || t("never_seen")}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {device?.online ? <Badge tone="ok">{t("online")}</Badge> : <Badge tone="muted">{t("offline")}</Badge>}
            <Button variant="outline" onClick={() => forget.mutate()} disabled={forget.isPending}>
              <Trash2Icon className="size-4" />
              {t("forget_device")}
            </Button>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Stat label={t("last_seen")} value={device?.last_seen_at ? new Date(device.last_seen_at * 1000).toLocaleString() : "—"} />
          <Stat label={t("run_started")} value={device?.run_started_at ? new Date(device.run_started_at * 1000).toLocaleString() : "—"} />
          <Stat label={t("device_address")} value={entry.address} mono />
        </div>
      </Card>

      {device && !device.registered && (
        <div className="rounded-xl border border-amber-500/40 p-4 text-sm text-amber-600 dark:text-amber-400">
          {t("device_not_registered")}
        </div>
      )}

      <Card className="space-y-3">
        <div className="text-sm font-medium">{t("send_call")}</div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            value={tool}
            onChange={(event) => setTool(event.target.value)}
            placeholder={DEFAULT_TOOL}
            aria-label={t("tool_name")}
            className="font-mono text-xs sm:w-40"
          />
          <Input
            className="min-w-0 flex-1 font-mono text-xs"
            value={argsText}
            onChange={(event) => setArgsText(event.target.value)}
            aria-label={t("arguments")}
          />
        </div>
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
                  {["queued", "received"].includes(call.status) && (
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
                  {attachmentBytes(plaintext) !== null &&
                    (attachment !== null ? (
                      <pre className="overflow-x-auto font-mono text-xs">{JSON.stringify(attachment, null, 2)}</pre>
                    ) : (
                      <div className="space-y-2">
                        <div className="text-muted-foreground">{t("attachment_hint")}</div>
                        <Button variant="outline" onClick={() => loadAttachment.mutate()} disabled={loadAttachment.isPending}>
                          {t("attachment_load")}
                        </Button>
                        {loadAttachment.error && <div className="text-destructive">{loadAttachment.error.message}</div>}
                      </div>
                    ))}
                </div>
              )}
            </div>
          ))}
          {archived.length > 0 && (
            <div className="space-y-2 border-t pt-3">
              <div className="text-sm font-medium">{t("local_history")}</div>
              <p className="text-xs text-muted-foreground">{t("local_history_body")}</p>
              {archived.map((call) => (
                <details key={call.call_id} className="rounded-lg bg-muted/50 p-3 text-xs">
                  <summary className="cursor-pointer font-mono">
                    {call.call_id.slice(0, 8)} · {call.name}
                  </summary>
                  <pre className="mt-2 overflow-x-auto font-mono text-xs">{JSON.stringify(call.result, null, 2)}</pre>
                </details>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
