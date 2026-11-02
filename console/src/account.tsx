// Registers this browser's public keys once, and tells the UI when it cannot
// sign (a browser that never held the key can read nothing meaningful).
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthMini } from "auth-mini-react-components";
import { api, type Me } from "./api";
import { localKeys, signRegistration } from "./keystore";

type State = "loading" | "ready" | "mismatch" | "error";

interface AccountContextValue {
  state: State;
  account: Me | null;
  error: string | null;
  retry: () => void;
}

const AccountContext = createContext<AccountContextValue>({ state: "loading", account: null, error: null, retry: () => {} });

export function AccountProvider({ children }: { children: ReactNode }) {
  const { sdk } = useAuthMini();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const me = useQuery({ queryKey: ["me"], queryFn: () => api<Me>(sdk as never, "/api/me"), enabled: Boolean(sdk) });

  useEffect(() => {
    let cancelled = false;
    async function ensure() {
      if (!me.data || !sdk) return;
      try {
        const keys = await localKeys();
        if (me.data.registered) return;
        const challenge = await api<{ nonce: string }>(sdk as never, "/api/account/challenge");
        const signed = await signRegistration(me.data.account_id, challenge.nonce, Math.floor(Date.now() / 1000));
        await api(sdk as never, "/api/account", { method: "PUT", body: JSON.stringify(signed) });
        if (!cancelled) {
          setError(null);
          await queryClient.invalidateQueries({ queryKey: ["me"] });
        }
        void keys;
      } catch (value) {
        if (!cancelled) setError(value instanceof Error ? value.message : "registration failed");
      }
    }
    void ensure();
    return () => {
      cancelled = true;
    };
  }, [me.data, sdk, queryClient, attempt]);

  const value = useMemo<AccountContextValue>(() => {
    const keys = me.data;
    if (error) return { state: "error", account: keys ?? null, error, retry: () => setAttempt((n) => n + 1) };
    if (!keys) return { state: "loading", account: null, error: null, retry: () => {} };
    if (!keys.registered) return { state: "loading", account: keys, error: null, retry: () => {} };
    return { state: "mismatch", account: keys, error: null, retry: () => {} };
  }, [me.data, error]);

  return <AccountContext.Provider value={value}>{children}</AccountContext.Provider>;
}

export function useAccount() {
  return useContext(AccountContext);
}

/** True when this browser holds the key the server has on file. */
export async function holdsAccountKey(account: Me | null): Promise<boolean> {
  if (!account?.sig_pub) return false;
  const keys = await localKeys();
  return keys.sigPub === account.sig_pub;
}
