# Ethic APK Guard

A local-first Android preflight for a selected APK. It explains whether the APK appears able to update the installed app without erasing its data, before the user opens an installer.

It reads the selected file through Android's system picker and compares package name, version code, signing certificates, declared signing history, minimum Android version, native ABIs, `classes.dex`, and newly requested dangerous permissions. It also reports update-relevant security changes: a debuggable candidate, newly allowed cleartext HTTP traffic, newly allowed app backups, a lower target SDK, and newly exported components.

The user can explicitly share a text-only technical report. The confirmation explains that it contains the package identifier, versions, an abbreviated certificate fingerprint, and detected changes; it never attaches the APK or a device-wide app list.

After analysis, an explicit action can hand that one selected APK to Android's system installer. Ethic APK Guard does not install or uninstall anything itself, never bypasses Android's final confirmation, and blocks its update action when the signing certificates are incompatible. A package with no installed match may be handed to Android only as a clearly labelled new application. Android may require the user to allow this app as an installation source first. It identifies common APKS and XAPK containers and explains their limit; installing split-package bundles is outside this deliberately single-APK flow.

After the local analysis, the user can separately and explicitly ask for public F-Droid context. Only then the app uses HTTPS to request the selected package identifier and version code from F-Droid's public package API, public metadata repository, and public reproducible-verification records. It never uploads the APK, its contents, its hash, or an inventory of installed apps. The remote servers may log the request. The report labels this material as public registry data: absence of an Anti-Feature or a verification record is not a safety certification, and presence in F-Droid is not a claim that the selected file is authentic.

The verdict is deliberately conservative: Android remains the final authority for installation, especially for split APKs and signing-certificate rotation.

`QUERY_ALL_PACKAGES` is declared solely because Android otherwise hides a dynamically selected package from the comparison API. The app does not display, persist, or transmit a device-wide app list.

`INTERNET` is declared solely for the per-query, consented F-Droid lookup described above; the complete update-compatibility analysis works without a network connection.

This project is released under GNU GPLv3 or any later version. See [COPYING](COPYING). An F-Droid recipe has been submitted for review; this does not imply acceptance or publication. F-Droid must still complete its metadata, reproducibility, and review work.

Release signing is local and opt-in. Provide `KEYSTORE_PATH`, `KEY_ALIAS`, `STORE_PASSWORD`, and `KEY_PASSWORD` to Gradle; no private key or password is committed. The public source repository is the reproducible handoff, while a distributed APK must be accompanied by its checksum and signing-certificate information.

## Intended distinction

This is not an APK installer, editor, general package manager, or generic APK inspector. Its single user-facing question is: **can this exact APK replace the app installed on this device without an avoidable loss of data, and what security-relevant changes accompany it?**

The answer is based on local evidence and remains conservative. Android's package installer is the final authority, particularly for split packages and signing-certificate rotation.
