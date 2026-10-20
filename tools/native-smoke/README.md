# Native application entry smoke

Run against the binary you intend to test, with a new output directory:

```sh
python3 tools/native-smoke/smoke.py --binary target/release/effectcraft --out /tmp/ec-smoke-run
```

Windows uses `python` and `effectcraft.exe`. Linux without a desktop uses `xvfb-run -a`.
The script requires Python 3.9+ and its standard library, plus `netstat` on Windows
or `lsof` on macOS/Linux to verify the child's control-port ownership. Each child gets its own
`EFFECTCRAFT_CONFIG_DIR`; no preferences or default audio routing are changed. Only
the child created by this script is quit or killed. Runtime is bounded, including
startup, control calls and shutdown. The output directory retains the report, child
logs, generated fixture/project and rendered PNG, including on failure.

This exercises the desktop executable's real startup, control server, media import,
save, frame rendering, playback past 12 seconds to the 359/24-second CTI endpoint,
replay, loop wrap, stop, and a second process opening the saved project on launch.
The audio fixture is an original procedural stereo chirp under MIT OR Apache-2.0;
no binary asset is checked in. The endpoint is the last frame's time; the media span
is 15 seconds. `--require-audio` additionally requires active audio telemetry past
12 seconds and non-silent meters. It does **not** verify sound reaching a device.

`workflow-proposal.yml` is a reviewable three-OS integration proposal, deliberately
outside `.github/workflows` until the coordinating CI owner integrates it. Existing
argument tests exit before opening a window; export filesystem tests exercise their
own test executable; neither checks the native app's launch/control/import/playback
path. The existing browser smoke checks the web app and Web Audio counters, not
native output. Hosted runners may have no audio output; this proposal checks the
desktop path without requiring one. Device output needs a separately provisioned
runner and process-filtered or otherwise isolated capture. No macOS or Linux runtime
pass is implied by preparing this harness.

This focused smoke does not cover interactive drag/drop, native dialogs, GPU model
coverage, installers, all media formats, browser platforms or exhaustive parity.
