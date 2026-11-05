// The browser half: one sidebar row and the page it selects.
//
// The sidebar's `panellist` entry and the layout's `main` keyed slot address the
// same id, which is the whole wiring between the row and the page. Both
// registrations go through `slots.inject`, so they appear when the shell that
// owns those slots is mounted and leave when this plugin is disabled.
import { ExeIcon } from "./icon.tsx";
import { ExePanel } from "./panel.tsx";

export const inject = ["slots"];

/** Panel id in the layout's `main` slot, and the sidebar row that selects it. */
export const PANEL_ID = "exe";

interface SlotRegistry {
  inject(name: string, contribute: () => () => void): void;
  register(
    options: { name: string; key?: string; id?: string; order?: number; label?: string },
    component: unknown,
  ): () => void;
}

interface ClientContext {
  slots: SlotRegistry;
}

export function apply(ctx: ClientContext): void {
  ctx.slots.inject("main", () => ctx.slots.register({ name: "main", key: PANEL_ID }, ExePanel));
  ctx.slots.inject("sidebar.panellist", () =>
    ctx.slots.register({ name: "sidebar.panellist", id: PANEL_ID, order: 40, label: "eXe" }, ExeIcon),
  );
}
