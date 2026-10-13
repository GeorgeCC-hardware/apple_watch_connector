# Changelog

## Unreleased — experimental release candidate

Source versions: Companion **1.0.86+87**, Android Bridge **0.2.429 / 629**,
shared Rust crates **0.1.1**. No public stable release is declared.

- Discover every model using the supported NetworkRelay advertisement format,
  independently of the display catalog and setup compatibility range.
- Bind authenticated Watch ProductType to the selected advertisement and retain
  its runtime ChipID/ModelNumber within the pairing generation; remove Ultra 2
  identity constants from the shared Android/Linux/Windows setup path.
- Restore setup from the sealed pair's model and observed IDS Hello version;
  remove invented Ultra 2 metadata and retry data-first setup after Hello.
- Display Ultra 1 identity and keep unknown models visible through a generic
  fallback. Ultra 1 SMP timeout from issue #4 still requires hardware diagnosis.
- Preserve early SMP traffic across control/pairing IKE and the final ACK;
  consume Security Request during feature negotiation without duplicate requests,
  extending deadlines or changing the existing OOB/Secure Connections policy.
- Bound deferred SMP queues and fail promptly on controller EOF. Linux HCI broker
  metadata distinguishes successful socket submission from Java pipe writes;
  relay only the bounded metadata schema into the protocol journal, without keys
  or packet payloads. Hardware acceptance on Ultra 1 remains pending.
- Share the Flutter connection UI across Android, Linux, Windows and macOS.
- Linux: pairing, activation and saved-pair reconnect verified on Mint 22.3 / Intel AX211.
- Windows: USB HCI pairing, activation and encrypted reconnect verified on Windows 10 / Realtek `0bda:b00e`; user-scoped DPAPI storage.
- Discover/select the Windows controller instead of using a personal PnP ID;
  refresh USB availability after hotplug and bind transport to the chosen identity.
- Stage the complete Windows native/protocol/Java bundle before replacing it.
- Show backend-declared feature availability and hide unsupported Watch service sections.
- Replace activation captures with deterministic synthetic serializer fixtures;
  remove personal device/network identifiers and repository-local AI tooling.
- Refresh English/Russian README and release instructions for all four platforms.

macOS pairing/IDS, desktop Watch application services, complete Health and
Watch.app parity remain incomplete. Distribution signing, CI, package audits
for Windows/macOS and candidate hardware/upgrade acceptance are still required.
See [build and release](docs/BUILD_AND_RELEASE.md) for the support matrix.
