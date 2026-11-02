#ifndef EXE_MOBILE_H
#define EXE_MOBILE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Returns the agent version; free with exe_agent_free.
char *exe_agent_version(void);

/// Returns this device's address (base58 Ed25519 public key); free with
/// exe_agent_free. The shell shows it so a human can add the device in the
/// console. There is no pairing code.
char *exe_agent_address(const char *config_dir);

void exe_agent_free(char *value);

/// Blocks forever serving calls. Writes the address to <config_dir>/address.txt.
int exe_agent_run(const char *config_dir, const char *cloud);

#ifdef __cplusplus
}
#endif

#endif
