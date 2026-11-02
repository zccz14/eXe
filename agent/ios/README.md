# eXe iOS shell

`ExeAgent.swift` + `exe_mobile.h` wrap the same Rust core the desktop binary uses.
Build the static library and add these files to an Xcode app target:

```sh
cargo build -p exe-mobile --release --target aarch64-apple-ios
cargo build -p exe-mobile --release --target aarch64-apple-ios-sim
# link libexe_mobile.a, add exe_mobile.h as the bridging header
```

There is no store signing in this repository: the iOS app target, its
entitlements and its distribution remain the owner's step.
