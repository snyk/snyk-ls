IDE-1898: The Eclipse plugin shall successfully complete LSP initialization regardless of the number of workspace folders.
IDE-1898: When a feature flag is deactivated, the IDE plugin shall observe the change within 60 seconds.
IDE-1898: When a user authenticates, the IDE plugin shall immediately re-evaluate feature flags without waiting for any previously cached authentication failures to expire.
IDE-2089: snyk-ls shall set `SNYK_AUTODETECT_OSS=1` in the environment of every Snyk OSS CLI invocation so the CLI's os-flows extension can decide per-folder whether to also run an unmanaged scan.
IDE-2089: The CLI's `cli-extension-os-flows` extension shall, when `SNYK_AUTODETECT_OSS` is truthy and `--unmanaged` was not explicitly passed, inspect each input directory for C/C++ source, header, or build-system files and run an extra unmanaged scan alongside the managed scan when any are found.
IDE-2089: When the extension runs an extra unmanaged scan it shall return the unmanaged results alongside the managed results so both are presented to the user without per-folder IDE configuration.
