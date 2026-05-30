IDE-1898: The Eclipse plugin shall successfully complete LSP initialization regardless of the number of workspace folders.
IDE-1898: When a feature flag is deactivated, the IDE plugin shall observe the change within 60 seconds.
IDE-1898: When a user authenticates, the IDE plugin shall immediately re-evaluate feature flags without waiting for any previously cached authentication failures to expire.
IDE-2089: When an OSS scan starts on a folder that contains C/C++ source, header, or build-system files, the IDE plugin shall offer the user a one-time prompt to enable unmanaged scanning for that folder.
IDE-2089: The IDE plugin shall persist the user's response to the unmanaged-scan prompt per folder so the prompt is never shown again for that folder, even across IDE restarts.
IDE-2089: When unmanaged scanning is enabled for a folder, the IDE plugin shall pass `--unmanaged` to the Snyk OSS CLI on every subsequent OSS scan for that folder.
