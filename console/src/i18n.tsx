import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

export type Lang = "zh" | "en";

const copy = {
  zh: {
    devices_title: "设备",
    devices_intro: "云端只能投递信封，不能命令。每一次执行都由设备本地固定的地址验证签名。",
    add_title: "添加设备",
    add_body: "在设备上运行 exe run，它会打印本机地址；把地址填到这里即可，不需要配对码。",
    device_address: "设备地址",
    label_device: "备注名",
    add_device: "添加",
    no_devices: "还没有设备。",
    devices_error: "读取失败：中继不可达，或这台机器的时钟偏差过大。",
    console_address: "本控制台地址",
    console_address_body: "这台设备的信任列表里要写的就是它。私钥只在这个浏览器里：换浏览器、清站点数据都会得到新地址，历史结果也就解不开了。",
    relay_unreachable: "连不上中继，或本机时钟与中继相差超过 5 分钟。",
    copy: "复制",
    copied: "已复制",
    download_title: "下载客户端",
    download_body: "在设备上运行 exe 即可；二进制发布在 GitHub Release，版本与云端一致。",
    download_fallback: "在 GitHub 上查看最新 Release",
    download_empty: "还没有发布任何版本。",
    download_hint: "下载由 GitHub Release 提供。",
    never_seen: "尚未上线",
    online: "在线",
    offline: "离线",
    send_call: "发起调用",
    tool_name: "工具名",
    arguments: "参数",
    run: "执行",
    calls: "调用记录",
    no_calls: "还没有调用。",
    cancel: "取消",
    remove_device: "移除设备",
    last_seen: "最后在线",
    policy_note: "签名来自你信任的地址就会执行；云端看不到工具与参数。shell 以设备用户身份运行，没有沙箱。",
    sent: "已排队",
    delivered: "已投递",
    received: "已收到",
    succeeded: "成功",
    failed: "失败",
    cancelled: "已取消",
    expired_state: "已过期",
    language: "语言",
    sealed_call: "（密封）",
  },
  en: {
    devices_title: "Devices",
    devices_intro: "The relay may deliver envelopes, never commands. Every execution verifies against an address pinned on the device.",
    add_title: "Add a device",
    add_body: "Run exe run on the device; it prints its address. Paste it here — there is no pairing code.",
    device_address: "Device address",
    label_device: "Label",
    add_device: "Add",
    no_devices: "No devices yet.",
    devices_error: "Could not load: the relay is unreachable, or this machine's clock is off by more than five minutes.",
    console_address: "This console's address",
    console_address_body: "This is what goes into the device's trust list. The key only exists in this browser: another browser, or cleared site data, is a new address — and old results stay sealed.",
    relay_unreachable: "The relay is unreachable, or this clock is more than five minutes off.",
    copy: "Copy",
    copied: "Copied",
    download_title: "Download the client",
    download_body: "Run exe on the device. Binaries are published on GitHub Releases and share the relay's version.",
    download_fallback: "Open the latest release on GitHub",
    download_empty: "No release has been published yet.",
    download_hint: "Downloads are served from GitHub Releases.",
    never_seen: "never seen",
    online: "online",
    offline: "offline",
    send_call: "Send a call",
    tool_name: "Tool name",
    arguments: "Arguments",
    run: "Run",
    calls: "Calls",
    no_calls: "No calls yet.",
    cancel: "Cancel",
    remove_device: "Remove device",
    last_seen: "Last seen",
    policy_note: "A signature from an address you trust runs. The relay never sees the tool or its arguments; shell runs as the device user, with no sandbox.",
    sent: "queued",
    delivered: "delivered",
    received: "received",
    succeeded: "succeeded",
    failed: "failed",
    cancelled: "cancelled",
    expired_state: "expired",
    language: "Language",
    sealed_call: "(sealed)",
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
