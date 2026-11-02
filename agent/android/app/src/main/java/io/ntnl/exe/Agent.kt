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
    external fun nativeRun(configDir: String, baseUrl: String): Int

    fun start(configDir: String, baseUrl: String) {
        Thread({ nativeRun(configDir, baseUrl) }, "exe-agent").start()
    }
}
