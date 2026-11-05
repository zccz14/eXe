// The sidebar glyph: a device prompt — the one thing this page is about.
import type { ReactElement } from "react";

export function ExeIcon(props: { size?: number; active?: boolean }): ReactElement {
  const size = props.size ?? 18;
  const opacity = props.active === false ? 0.72 : 1;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ opacity }}>
      <rect x="3" y="4.5" width="18" height="15" rx="3" stroke="currentColor" strokeWidth="1.6" />
      <path
        d="M7.5 10l2.6 2.1-2.6 2.1M12.4 14.4h4.1"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
