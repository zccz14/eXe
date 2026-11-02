import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useAuthMini } from "auth-mini-react-components";
import { ShieldCheckIcon } from "lucide-react";
import { api, type PairingView } from "../api";
import { useCopy } from "../i18n";
import { Badge, Button, Card, Input, Stat } from "../ui";

export function PairPage() {
  const t = useCopy();
  const { sdk } = useAuthMini();
  const [code, setCode] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [label, setLabel] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const pairing = useQuery({
    queryKey: ["pairing", submitted],
    queryFn: () => api<PairingView>(sdk as never, `/api/pairings/${encodeURIComponent(submitted)}`),
    enabled: submitted.length >= 8,
    retry: 0,
    refetchInterval: (query) => (query.state.data?.status === "pending" ? 3000 : false),
  });

  const approve = useMutation({
    mutationFn: (deviceLabel: string) =>
      api<{ sas: string }>(sdk as never, `/api/pairings/${encodeURIComponent(submitted)}`, {
        method: "POST",
        body: JSON.stringify({ label: deviceLabel || undefined }),
      }),
    onSuccess: () => setNotice(t("pair_approved")),
    onError: (error: Error) => setNotice(error.message),
  });

  const deny = useMutation({
    mutationFn: () => api<void>(sdk as never, `/api/pairings/${encodeURIComponent(submitted)}`, { method: "DELETE" }),
    onSuccess: () => setNotice(t("pair_denied")),
    onError: (error: Error) => setNotice(error.message),
  });

  const data = pairing.data;

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">{t("approve_title")}</h1>
        <p className="text-sm text-muted-foreground">{t("approve_intro")}</p>
      </header>

      <form
        className="flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setNotice(null);
          setSubmitted(code.trim());
        }}
      >
        <Input value={code} onChange={(event) => setCode(event.target.value)} placeholder="A1B2-C3D4-E5F6" className="font-mono" />
        <Button type="submit" disabled={code.trim().length < 8}>
          {t("lookup")}
        </Button>
      </form>

      {pairing.error && <Card className="text-sm text-destructive">{(pairing.error as Error).message}</Card>}

      {data && (
        <Card className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="font-medium">{data.hostname}</div>
            <Badge tone={data.status === "pending" ? "warn" : data.status === "approved" ? "ok" : "bad"}>
              {data.status === "pending" ? t("pair_pending") : data.status === "approved" ? t("pair_approved") : data.status === "denied" ? t("pair_denied") : t("pair_expired")}
            </Badge>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <Stat label={t("platform")} value={data.platform} />
            <Stat label={t("version")} value={data.version} />
            <Stat label={t("expires")} value={new Date(data.expires_at * 1000).toLocaleTimeString()} />
            <Stat label={t("code")} value={data.user_code} mono />
          </div>
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-3">
            <div className="flex items-center gap-2 text-sm font-medium">
              <ShieldCheckIcon className="size-4" />
              {t("sas")}: <span className="font-mono text-base tracking-widest">{data.sas}</span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{t("sas_hint")}</p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input value={label} onChange={(event) => setLabel(event.target.value)} placeholder={t("label_device")} />
            <Button onClick={() => approve.mutate(label)} disabled={data.status !== "pending" || approve.isPending}>
              {t("approve")}
            </Button>
            <Button variant="outline" onClick={() => deny.mutate()} disabled={data.status !== "pending" || deny.isPending}>
              {t("deny")}
            </Button>
          </div>
          {notice && <p className="text-sm text-muted-foreground">{notice}</p>}
        </Card>
      )}
    </div>
  );
}
