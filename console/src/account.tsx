// Registers this browser's address once, and tells the UI when it cannot sign
// (a browser that never held the key can read nothing meaningful).
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthMini } from "auth-mini-react-components";
import { api, type Me } from "./api";
import { localAddress, localIdentity, signRegistration } from "./keystore";

type State = "loading" | "ready" | "mismatch" | "error";

interface AccountContextValue {
  state: State;
  account: Me | null;
  address: string | null;
  error: string | null;
  retry: () => void;
}

const AccountContext = createContext<AccountContextValue>({ state: "loading", account: null, address: null, error: null, retry: () => {} });

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
        await localIdentity();
        if (me.data.registered) return;
        const challenge = await api<{ nonce: string }>(sdk as never, "/api/account/challenge");
        const signed = await signRegistration(me.data.account_id, challenge.nonce, Math.floor(Date.now() / 1000));
        await api(sdk as never, "/api/account", { method: "PUT", body: JSON.stringify(signed) });
        if (!cancelled) {
          setError(null);
          await queryClient.invalidateQueries({ queryKey: ["me"] });
        }
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
    const account = me.data ?? null;
    const retry = () => setAttempt((n) => n + 1);
    if (error) return { state: "error", account, address: null, error, retry };
    if (!account) return { state: "loading", account: null, address: null, error: null, retry };
    return { state: account.registered ? "ready" : "loading", account, address: account.address, error: null, retry };
  }, [me.data, error]);

  return <AccountContext.Provider value={value}>{children}</AccountContext.Provider>;
}

export function useAccount() {
  return useContext(AccountContext);
}

/** True when this browser holds the key the relay has on file. */
export async function holdsAccountKey(account: Me | null): Promise<boolean> {
  if (!account?.address) return false;
  return (await localAddress()) === account.address;
}
