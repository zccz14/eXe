// The page itself: pure presentation, no fetching. Everything it needs arrives
// as props, which is what makes it testable without a browser.
import { useState, type ReactElement } from "react";
import type { DeviceRow, EditOp, ExeState } from "../contract.ts";

export interface ExeViewProps {
  state: ExeState | null;
  error: string | null;
  busy: boolean;
  onEdit(op: EditOp): void;
  onReload(): void;
}

const mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

const border = "1px solid color-mix(in srgb, currentColor 16%, transparent)";

const s = {
  page: {
    height: "100%",
    overflowY: "auto",
    padding: "24px 28px 48px",
    fontSize: 13,
    lineHeight: 1.55,
  },
  header: {
    display: "flex",
    alignItems: "baseline",
    gap: 12,
    marginBottom: 4,
  },
  title: { fontSize: 20, fontWeight: 600, margin: 0 },
  subtitle: { opacity: 0.6 },
  toolbar: { marginLeft: "auto", display: "flex", gap: 8 },
  card: {
    border,
    borderRadius: 10,
    padding: "16px 18px",
    marginTop: 18,
    display: "grid",
    gap: 10,
  },
  cardTitle: { fontSize: 13, fontWeight: 600, margin: 0, letterSpacing: "0.01em" },
  hint: { opacity: 0.65, margin: 0 },
  address: { fontFamily: mono, fontSize: 15, wordBreak: "break-all" as const, letterSpacing: "0.01em" },
  code: {
    fontFamily: mono,
    fontSize: 12.5,
    background: "color-mix(in srgb, currentColor 7%, transparent)",
    borderRadius: 6,
    padding: "6px 8px",
    overflowX: "auto" as const,
    whiteSpace: "pre" as const,
  },
  row: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    padding: "6px 0",
    borderTop: "1px solid color-mix(in srgb, currentColor 10%, transparent)",
  },
  label: { minWidth: 96, fontWeight: 500 },
  rowAddress: { fontFamily: mono, fontSize: 12, opacity: 0.85, wordBreak: "break-all" as const, flex: 1 },
  form: { display: "flex", flexWrap: "wrap" as const, gap: 8, marginTop: 2 },
  input: {
    flex: "1 1 160px",
    minWidth: 120,
    padding: "6px 9px",
    borderRadius: 6,
    border,
    background: "transparent",
    color: "inherit",
    font: "inherit",
  },
  button: {
    padding: "5px 11px",
    borderRadius: 6,
    border,
    background: "transparent",
    color: "inherit",
    font: "inherit",
    cursor: "pointer",
  },
  primary: {
    padding: "5px 12px",
    borderRadius: 6,
    border,
    background: "color-mix(in srgb, currentColor 10%, transparent)",
    color: "inherit",
    font: "inherit",
    cursor: "pointer",
  },
  danger: {
    padding: "3px 9px",
    borderRadius: 6,
    border: "1px solid color-mix(in srgb, #d33 45%, transparent)",
    background: "transparent",
    color: "inherit",
    font: "inherit",
    cursor: "pointer",
  },
  banner: {
    marginTop: 14,
    border: "1px solid color-mix(in srgb, #d33 45%, transparent)",
    borderRadius: 8,
    padding: "9px 12px",
    whiteSpace: "pre-wrap" as const,
  },
  badge: { fontSize: 11, opacity: 0.6, fontFamily: mono },
} as const;

function CopyButton({ value, label = "复制" }: { value: string; label?: string }): ReactElement {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      style={s.button}
      onClick={() => {
        void navigator.clipboard
          ?.writeText(value)
          .then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          })
          .catch(() => undefined);
      }}
    >
      {copied ? "已复制" : label}
    </button>
  );
}

function AddForm(props: {
  busy: boolean;
  first: string;
  second: string;
  action: string;
  onSubmit(first: string, second: string): void;
}): ReactElement {
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  return (
    <form
      style={s.form}
      onSubmit={(event) => {
        event.preventDefault();
        if (first.trim().length === 0 || second.trim().length === 0) return;
        props.onSubmit(first.trim(), second.trim());
        setFirst("");
        setSecond("");
      }}
    >
      <input
        style={s.input}
        placeholder={props.first}
        value={first}
        disabled={props.busy}
        onChange={(event) => setFirst(event.target.value)}
        aria-label={props.first}
      />
      <input
        style={s.input}
        placeholder={props.second}
        value={second}
        disabled={props.busy}
        onChange={(event) => setSecond(event.target.value)}
        aria-label={props.second}
      />
      <button style={s.primary} type="submit" disabled={props.busy}>
        {props.action}
      </button>
    </form>
  );
}

function Address({ value }: { value: string }): ReactElement {
  return <code style={s.address}>{value}</code>;
}

/** The caller half: the address another device has to trust. */
function CallerCard(props: { state: ExeState; busy: boolean }): ReactElement {
  const { caller } = props.state;
  return (
    <section style={s.card}>
      <h2 style={s.cardTitle}>本机调用方地址</h2>
      {caller.address === undefined ? (
        <>
          <p style={s.hint}>还没有调用方钥匙，其它设备暂时无处可信任。</p>
          {caller.error !== undefined && <div style={s.banner}>{caller.error}</div>}
          <pre style={s.code}>exe mcp init</pre>
        </>
      ) : (
        <>
          <p style={s.hint}>把这行地址加到每台设备上（在设备上执行），它们便接受这台 harness 的指令。</p>
          <div style={s.row}>
            <Address value={caller.address} />
            <CopyButton value={caller.address} />
          </div>
          <pre style={s.code}>{`exe trust ${caller.address}`}</pre>
          <span style={s.badge}>
            钥匙来源：{caller.source ?? "—"} · 中继：{caller.endpoints.join(" , ") || "—"}
          </span>
        </>
      )}
    </section>
  );
}

/** The device half: this machine as an eXe device, and who may command it. */
function DeviceCard(props: { state: ExeState; busy: boolean; onEdit(op: EditOp): void }): ReactElement {
  const { device } = props.state;
  return (
    <section style={s.card}>
      <h2 style={s.cardTitle}>本机作为设备</h2>
      {!device.available ? (
        <>
          <p style={s.hint}>这台机器还不是 eXe 设备（没有 {device.path}）。</p>
          <pre style={s.code}>exe</pre>
        </>
      ) : (
        <>
          {device.address !== undefined && (
            <>
              <p style={s.hint}>它的地址——其它调用方要 reach 它，就填这串。</p>
              <div style={s.row}>
                <Address value={device.address} />
                <CopyButton value={device.address} />
              </div>
            </>
          )}
          {device.error !== undefined && <div style={s.banner}>{device.error}</div>}
          <p style={s.hint}>
            信任的调用方（{device.trust.length}）：只有这里的地址能在这台机器上执行命令。设备每 2 秒热读配置，改完即生效。
          </p>
          {device.trust.length === 0 && <span style={s.badge}>还没有信任任何调用方</span>}
          {device.trust.map((address) => (
            <div style={s.row} key={address}>
              <span style={s.rowAddress}>{address}</span>
              <button
                type="button"
                style={s.danger}
                disabled={props.busy}
                onClick={() => props.onEdit({ op: "trust.remove", address })}
              >
                取消信任
              </button>
            </div>
          ))}
          <AddForm
            busy={props.busy}
            first="调用方地址（base58）"
            second="再填一次以确认"
            action="信任"
            onSubmit={(address, confirm) => {
              if (address !== confirm) return;
              props.onEdit({ op: "trust.add", address });
            }}
          />
        </>
      )}
    </section>
  );
}

/** The caller's own address book: which devices this harness may reach. */
function DevicesCard(props: { state: ExeState; busy: boolean; onEdit(op: EditOp): void }): ReactElement {
  const { devices } = props.state;
  return (
    <section style={s.card}>
      <h2 style={s.cardTitle}>可访问的设备</h2>
      <p style={s.hint}>
        这台 harness 记得的设备（写成标签，模型调用时用它）。设备那侧还要把这个页面上的调用方地址加进它的信任列表。
      </p>
      {devices.length === 0 && <span style={s.badge}>还没有配置设备</span>}
      {devices.map((row: DeviceRow) => (
        <div style={s.row} key={row.label}>
          <span style={s.label}>{row.label}</span>
          <span style={s.rowAddress}>{row.address}</span>
          {row.source === "config" ? (
            <span style={s.badge}>来自插件配置</span>
          ) : (
            <button
              type="button"
              style={s.danger}
              disabled={props.busy}
              onClick={() => props.onEdit({ op: "device.remove", label: row.label })}
            >
              移除
            </button>
          )}
        </div>
      ))}
      <AddForm
        busy={props.busy}
        first="标签（如 macmini）"
        second="设备地址（base58）"
        action="添加"
        onSubmit={(label, address) => props.onEdit({ op: "device.set", label, address })}
      />
    </section>
  );
}

export function ExeView(props: ExeViewProps): ReactElement {
  return (
    <div style={s.page}>
      <header style={s.header}>
        <h1 style={s.title}>eXe</h1>
        <span style={s.subtitle}>这台 harness 的钥匙，与它够得着的设备</span>
        <span style={s.toolbar}>
          <button type="button" style={s.button} onClick={props.onReload} disabled={props.busy}>
            {props.busy ? "处理中…" : "刷新"}
          </button>
        </span>
      </header>
      {props.error !== null && <div style={s.banner}>{props.error}</div>}
      {props.state === null ? (
        <p style={s.hint}>载入中…</p>
      ) : (
        <>
          <CallerCard state={props.state} busy={props.busy} />
          <DeviceCard state={props.state} busy={props.busy} onEdit={props.onEdit} />
          <DevicesCard state={props.state} busy={props.busy} onEdit={props.onEdit} />
        </>
      )}
    </div>
  );
}
