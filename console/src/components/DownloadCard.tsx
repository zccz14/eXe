import { useQuery } from "@tanstack/react-query";
import { DownloadIcon } from "lucide-react";
import { apiUrl, publicApi, type LatestRelease } from "../api";
import { useCopy } from "../i18n";
import { Card } from "../ui";

const TARGETS = [
  { target: "aarch64-apple-darwin", label: "macOS Apple Silicon", ext: "tar.gz" },
  { target: "x86_64-apple-darwin", label: "macOS Intel", ext: "tar.gz" },
  { target: "x86_64-unknown-linux-gnu", label: "Linux x86_64", ext: "tar.gz" },
  { target: "aarch64-unknown-linux-gnu", label: "Linux arm64", ext: "tar.gz" },
  { target: "x86_64-pc-windows-msvc", label: "Windows x86_64", ext: "zip" },
] as const;

function size(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

/** Downloads come from the relay, which resolves the latest GitHub Release. */
export function DownloadCard() {
  const t = useCopy();
  const releases = useQuery({
    queryKey: ["releases"],
    queryFn: () => publicApi<LatestRelease>("/api/releases/latest"),
    retry: 0,
    staleTime: 60_000,
  });
  const data = releases.data;
  const assets = data?.assets ?? [];
  const file = (target: string, ext: string) => assets.find((asset) => asset.name === `exe-${target}.${ext}`);
  const available = TARGETS.filter((item) => file(item.target, item.ext));

  return (
    <Card className="space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        <DownloadIcon className="size-4" />
        {t("download_title")}
        {data?.version && <span className="text-xs font-normal text-muted-foreground">v{data.version}</span>}
      </div>
      <p className="text-sm text-muted-foreground">{t("download_body")}</p>

      {available.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {available.map(({ target, label, ext }) => {
            const archive = file(target, ext)!;
            const checksum = assets.find((asset) => asset.name === `${archive.name}.sha256`);
            return (
              <div key={target} className="flex min-w-[11rem] flex-col gap-1 rounded-lg border border-border px-3 py-2">
                <a className="text-sm font-medium hover:underline" href={apiUrl(archive.url)}>
                  {label}
                </a>
                <span className="text-xs text-muted-foreground">{size(archive.size)}</span>
                {checksum && (
                  <a className="text-xs text-muted-foreground underline underline-offset-2" href={apiUrl(checksum.url)}>
                    SHA-256
                  </a>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="space-y-1 text-sm">
          <p className="text-muted-foreground">{releases.isLoading ? "…" : t("download_empty")}</p>
          <a className="underline underline-offset-4" href={data?.release_url ?? "https://github.com/zccz14/eXe/releases/latest"}>
            {t("download_fallback")}
          </a>
        </div>
      )}
    </Card>
  );
}
