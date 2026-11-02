#!/bin/sh
# Builds exe.app from clients/macos.
#
#   scripts/build-app.sh            # release build into dist/exe.app
#   scripts/build-app.sh debug      # faster, for iterating
#
# The bundle identity is fixed on purpose: TCC remembers grants per code
# identity, so the identifier must never change between builds. Signing is ad-hoc
# here — a Developer ID signature is what makes those grants survive upgrades.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROFILE=${1:-release}
VERSION=$(node -p "require('$ROOT/package.json').version")
APP="$ROOT/dist/exe.app"

cd "$ROOT/clients/macos"
swift build -c "$PROFILE"
BIN=$(swift build -c "$PROFILE" --show-bin-path)/ExeApp

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/exe-app"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>io.ntnl.exe</string>
  <key>CFBundleName</key><string>eXe</string>
  <key>CFBundleDisplayName</key><string>eXe</string>
  <key>CFBundleExecutable</key><string>exe-app</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSAppleEventsUsageDescription</key>
  <string>eXe 用它检查并执行跨 App 的自动化（例如通过 System Events 操作界面）。</string>
</dict>
</plist>
PLIST

# Ad-hoc, but with a stable identifier: the identifier is what a TCC grant is
# filed under, and it must not depend on the build.
codesign --force --sign - --identifier io.ntnl.exe "$APP" >/dev/null

echo "built $APP ($VERSION)"
