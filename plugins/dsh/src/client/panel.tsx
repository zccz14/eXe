// The page's only stateful part: read the state, apply an edit, redraw. Every
// mutation returns the whole state, so the page never guesses what changed.
import { useCallback, useEffect, useState, type ReactElement } from "react";
import type { EditOp, ExeState } from "../contract.ts";
import { ExeView } from "./view.tsx";

const STATE_URL = "/exe/api/state";
const EDIT_URL = "/exe/api/edit";

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function failure(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: unknown };
    if (typeof body.error === "string" && body.error.length > 0) return body.error;
  } catch {
    // A non-JSON failure is still a failure; fall back to the status line.
  }
  return `请求失败（HTTP ${response.status}）`;
}

export function ExePanel(): ReactElement {
  const [state, setState] = useState<ExeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async (): Promise<void> => {
    try {
      const response = await fetch(STATE_URL, { cache: "no-store", headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(await failure(response));
      setState((await response.json()) as ExeState);
      setError(null);
    } catch (loadError) {
      setError(reason(loadError));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const edit = useCallback((op: EditOp): void => {
    void (async () => {
      setBusy(true);
      try {
        const response = await fetch(EDIT_URL, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(op),
        });
        if (!response.ok) throw new Error(await failure(response));
        setState((await response.json()) as ExeState);
        setError(null);
      } catch (editError) {
        setError(reason(editError));
      } finally {
        setBusy(false);
      }
    })();
  }, []);

  return (
    <ExeView
      state={state}
      error={error}
      busy={busy}
      onEdit={edit}
      onReload={() => {
        void load();
      }}
    />
  );
}
