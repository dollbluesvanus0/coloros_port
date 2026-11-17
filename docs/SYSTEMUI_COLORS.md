# SystemUI dark-keyguard color compatibility

ColorOS RMX3300_17.0.1.201(CN01), tested in DSU, ships 22 SystemUI color
values as theme attributes even though the referenced IDs are framework colors.
For example, the night variant of `color/materialColorOnSecondaryFixed` is
`?0x01960018`, while this framework defines that ID as
`android:color/system_on_secondary_fixed_dark`.

After rebooting in dark mode, `keyguard_settings_popup_menu` inflates an
ImageView whose tint calls `TypedArray.getColorStateList`. The unresolved
attribute throws `UnsupportedOperationException`, repeatedly killing SystemUI.
This was reproduced with the original, platform-signed SystemUI APK; it is
not sufficient to assume the resource error was introduced by APK rebuilding.

`bin/systemui_color_overlay.py` asks the bundled AAPT2 to inspect the actual
SystemUI and framework resource tables. It selects only color values encoded
as attributes whose IDs resolve to framework color resources. It emits a
resource-only RRO containing references by name, retaining each original
configuration (including night). Valid theme attributes, ordinary references
and other resource types are untouched. IDs and palette RGB values are not
hardcoded, so Android's wallpaper-dependent colors remain effective.

`_port::stage_systemui_color_compat` runs for Android 16/17 after device
overlays and APK rebuilding, before filesystem metadata and image packing.
It compiles and signs `system_ext/overlay/ColorOSSystemUIColorFix.apk`, verifies
its signature and labels the file as `vendor_overlay_file`. Existing partition
OverlayConfig files receive an enabled, immutable entry before existing entries
(as Android requires immutable overlays before mutable ones); absent configuration
files remain absent to preserve the other overlays' manifest defaults. If the
donor has no matching broken colors, no overlay is built and an old generated
overlay is removed from the image tree.

The RRO targets SDK 28 so preinstalled OEM resources without an overlayable
contract can be overlaid. It contains no code, components or permissions.
SystemUI and framework APKs are never rewritten or re-signed by this stage.
The generated image needs neither root nor a boot-time theme workaround.

AAPT2 and apksigner come from the existing `otatools/bin` toolchain. Tests can
override their paths using `PORT_SYSTEMUI_AAPT2` and `PORT_SYSTEMUI_APKSIGNER`.
No external download is part of the porting stage.

On-device validation: reboot with dark mode already enabled, check that the
RRO is enabled, resolve the affected color, switch to light and back to dark,
then verify a stable SystemUI process, no new crash exits and visible keyguard,
status and navigation windows. A separate KernelSU DSU module was used to
exercise the same RRO without flashing images. Its payload is guarded by the
DSU property and the original SystemUI hash. The APK payload and device logs
are local diagnostics, not repository assets.

Useful checks:

```sh
adb shell cmd overlay list --user 0 com.android.systemui
adb shell cmd overlay lookup --user 0 --verbose com.android.systemui \
    com.android.systemui:color/materialColorOnSecondaryFixed
adb shell dumpsys activity exit-info com.android.systemui
python3 -m unittest discover -s tests -p test_systemui_color_overlay.py -v
```

References: [AOSP runtime resource overlays](https://source.android.com/docs/core/runtime/rros)
and [OverlayManagerShellCommand](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/om/OverlayManagerShellCommand.java).
