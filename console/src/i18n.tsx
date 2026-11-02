import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

export type Lang = "zh" | "en";

const copy = {
  zh: {
    app: "eXe",
    nav_devices: "设备",
    nav_pair: "批准配对",
    devices_title: "设备",
    devices_intro: "云端只能请求，不能命令。每次执行都要通过设备本地固定的公钥验证。",
    connect_title: "连接一台新设备",
    connect_body: "在该设备上运行下面的命令，它会打印一个配对码。",
    pair_action: "输入配对码",
    no_devices: "还没有设备。",
    online: "在线",
    offline: "离线",
    revoked: "已撤销",
    label_device: "设备名称",
    approve: "批准",
    deny: "拒绝",
    approve_title: "批准配对",
    approve_intro: "确认配对码与设备终端显示的一致，并比对 SAS。",
    code: "配对码",
    lookup: "查询",
    sas: "SAS",
    sas_hint: "必须与设备终端上打印的 6 位数字完全一致。不一致就拒绝。",
    hostname: "主机名",
    platform: "平台",
    version: "版本",
    expires: "过期时间",
    pair_pending: "等待批准",
    pair_approved: "已批准",
    pair_denied: "已拒绝",
    pair_expired: "已过期",
    send_call: "发起调用",
    tool: "工具",
    arguments: "参数",
    run: "执行",
    calls: "调用记录",
    result: "结果",
    no_calls: "还没有调用。",
    cancel: "取消",
    revoke: "撤销设备",
    signer: "账号签名公钥",
    device_key: "设备签名公钥",
    last_seen: "最后在线",
    policy_note: "设备本地策略决定能不能执行；签名合法但策略不允许时，设备会回传拒绝原因。",
    sent: "已排队",
    delivered: "已投递",
    received: "已收到",
    succeeded: "成功",
    failed: "失败",
    cancelled: "已取消",
    expired_state: "已过期",
    language: "语言",
    account_missing: "这个浏览器没有账号私钥，无法签名",
    sealed_call: "（密封）",
    sealed_hint: "云端看不到调用内容；名字与参数只存在签发它的这个浏览器里。",
    key_missing_title: "这个浏览器不持有账号私钥",
    key_missing_body: "私钥只存在于创建它的浏览器里。换一台浏览器就看不到结果，也无法签发调用——这正是「云端不存私钥」的代价。",
  },
  en: {
    app: "eXe",
    nav_devices: "Devices",
    nav_pair: "Approve pairing",
    devices_title: "Devices",
    devices_intro: "The cloud may ask, never command. Every execution verifies against a key pinned on the device.",
    connect_title: "Connect a device",
    connect_body: "Run this on the device; it prints a pairing code.",
    pair_action: "Enter pairing code",
    no_devices: "No devices yet.",
    online: "online",
    offline: "offline",
    revoked: "revoked",
    label_device: "Device name",
    approve: "Approve",
    deny: "Deny",
    approve_title: "Approve pairing",
    approve_intro: "Check the code matches the device terminal and compare the SAS.",
    code: "Pairing code",
    lookup: "Look up",
    sas: "SAS",
    sas_hint: "Must match the six digits printed on the device exactly. Deny on mismatch.",
    hostname: "Hostname",
    platform: "Platform",
    version: "Version",
    expires: "Expires",
    pair_pending: "pending",
    pair_approved: "approved",
    pair_denied: "denied",
    pair_expired: "expired",
    send_call: "Send a call",
    tool: "Tool",
    arguments: "Arguments",
    run: "Run",
    calls: "Calls",
    result: "Result",
    no_calls: "No calls yet.",
    cancel: "Cancel",
    revoke: "Revoke device",
    signer: "Account signing key",
    device_key: "Device signing key",
    last_seen: "Last seen",
    policy_note: "The device's local policy decides. A valid signature with a denied tool returns a refusal.",
    sent: "queued",
    delivered: "delivered",
    received: "received",
    succeeded: "succeeded",
    failed: "failed",
    cancelled: "cancelled",
    expired_state: "expired",
    language: "Language",
    account_missing: "This browser does not hold the account key and cannot sign",
    sealed_call: "(sealed)",
    sealed_hint: "The cloud never sees call contents; names and arguments exist only in the browser that signed them.",
    key_missing_title: "This browser does not hold the account key",
    key_missing_body: "The private key only exists in the browser that created it. Another browser can neither read old results nor authorize new calls — that is the price of keeping private keys off the server.",
  },
} as const;

export type CopyKey = keyof (typeof copy)["zh"];

export const statusCopy = {
  queued: "sent",
  delivered: "delivered",
  received: "received",
  succeeded: "succeeded",
  failed: "failed",
  cancelled: "cancelled",
  expired: "expired_state",
} as const satisfies Record<string, CopyKey>;

const LanguageContext = createContext<{ lang: Lang; setLang: (lang: Lang) => void }>({ lang: "zh", setLang: () => {} });

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>(() => (localStorage.getItem("exe.lang") as Lang) || "zh");
  const value = useMemo(
    () => ({
      lang,
      setLang: (next: Lang) => {
        localStorage.setItem("exe.lang", next);
        setLang(next);
      },
    }),
    [lang],
  );
  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useLang() {
  return useContext(LanguageContext);
}

export function useCopy() {
  const { lang } = useLang();
  return (key: CopyKey) => copy[lang][key];
}
