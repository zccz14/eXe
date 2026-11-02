package io.ntnl.exe

/**
 * Thin shell over the Rust core. The protocol, the signature check and the
 * result sealing all live in `libexe_mobile.so`; this file only starts it.
 */
object Agent {
    init {
        System.loadLibrary("exe_mobile")
    }

    @JvmStatic
    external fun nativeRun(configDir: String, cloud: String): Int

    /** The address to paste into the console; null when the key cannot be created. */
    @JvmStatic
    external fun nativeAddress(configDir: String): String?

    fun start(configDir: String, cloud: String) {
        Thread({ nativeRun(configDir, cloud) }, "exe-agent").start()
    }

    fun address(configDir: String): String? = nativeAddress(configDir)
}
