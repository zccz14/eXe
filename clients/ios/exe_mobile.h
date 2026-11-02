#ifndef EXE_MOBILE_H
#define EXE_MOBILE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Returns the client version; free with exe_client_free.
char *exe_client_version(void);

/// Returns this device's address (base58 Ed25519 public key); free with
/// exe_client_free. The shell shows it so a human can add the device in the
/// console. There is no pairing code.
char *exe_client_address(const char *config_dir);

void exe_client_free(char *value);

/// Blocks forever serving calls. Writes the address to <config_dir>/address.txt.
int exe_client_run(const char *config_dir, const char *cloud);

#ifdef __cplusplus
}
#endif

#endif
