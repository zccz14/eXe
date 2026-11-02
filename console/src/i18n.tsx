import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

export type Lang = "zh" | "en";

const copy = {
  zh: {
    app: "eXe",
    nav_devices: "设备",
    devices_title: "设备",
    devices_intro: "云端只能投递信封，不能命令。每一次执行都由设备本地固定的地址验证签名。",
    add_title: "添加设备",
    add_body: "在设备上运行 exe run，它会打印本机地址；把地址填到这里即可，不需要配对码。",
    device_address: "设备地址",
    label_device: "备注名",
    add_device: "添加",
    no_devices: "还没有设备。",
    devices_error: "读取失败：请先登录，或稍后重试。",
    download_title: "下载客户端",
    download_body: "在设备上运行 exe 即可；二进制发布在 GitHub Release，版本与云端一致。",
    download_version: "最新版本",
    download_fallback: "在 GitHub 上查看最新 Release",
    download_empty: "还没有发布任何版本。",
    download_hint: "下载由 GitHub Release 提供。",
    never_seen: "尚未上线",
    online: "在线",
    offline: "离线",
    revoked: "已移除",
    send_call: "发起调用",
    tool: "工具",
    arguments: "参数",
    run: "执行",
    calls: "调用记录",
    result: "结果",
    no_calls: "还没有调用。",
    cancel: "取消",
    remove_device: "移除设备",
    last_seen: "最后在线",
    policy_note: "签名来自你信任的地址就会执行；云端看不到工具与参数。bash 以设备用户身份运行，没有沙箱。",
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
    devices_title: "Devices",
    devices_intro: "The relay may deliver envelopes, never commands. Every execution verifies against an address pinned on the device.",
    add_title: "Add a device",
    add_body: "Run exe run on the device; it prints its address. Paste it here — there is no pairing code.",
    device_address: "Device address",
    label_device: "Label",
    add_device: "Add",
    no_devices: "No devices yet.",
    devices_error: "Could not load: sign in first, or try again later.",
    download_title: "Download the client",
    download_body: "Run exe on the device. Binaries are published on GitHub Releases and share the relay's version.",
    download_version: "Latest",
    download_fallback: "Open the latest release on GitHub",
    download_empty: "No release has been published yet.",
    download_hint: "Downloads are served from GitHub Releases.",
    never_seen: "never seen",
    online: "online",
    offline: "offline",
    revoked: "removed",
    send_call: "Send a call",
    tool: "Tool",
    arguments: "Arguments",
    run: "Run",
    calls: "Calls",
    result: "Result",
    no_calls: "No calls yet.",
    cancel: "Cancel",
    remove_device: "Remove device",
    last_seen: "Last seen",
    policy_note: "A signature from an address you trust runs. The relay never sees the tool or its arguments; bash runs as the device user, with no sandbox.",
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
    sealed_hint: "The relay never sees call contents; names and arguments exist only in the browser that signed them.",
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
