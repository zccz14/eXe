#ifndef EXE_MOBILE_H
#define EXE_MOBILE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Returns the agent version; free with exe_agent_free.
char *exe_agent_version(void);
void exe_agent_free(char *value);

/// Blocks forever serving calls. Writes the pairing code to <config_dir>/pairing.txt.
int exe_agent_run(const char *config_dir, const char *base_url);

#ifdef __cplusplus
}
#endif

#endif
