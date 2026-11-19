#!/bin/bash
# Generate the same resource-only overlay verified on ColorOS 17.0.1 DSU.
_port::stage_systemui_color_compat() (
    local images_root="${1:-build/portrom/images}"
    case "${port_android_version:-}" in
        16|17) ;;
        *) return 0 ;;
    esac
    local systemui framework overlay_root target private_tmp aapt2 apksigner tool contexts
    systemui="$(find "${images_root}" -type f -name SystemUI.apk -print -quit)"
    framework="${images_root}/system/system/framework/framework-res.apk"
    [[ -f "${framework}" ]] || framework="${images_root}/system/framework/framework-res.apk"
    [[ -f "${systemui}" ]] || return 0
    [[ -f "${framework}" ]] || { echo "Missing framework-res for SystemUI colors" >&2; return 1; }
    aapt2="${PORT_SYSTEMUI_AAPT2:-otatools/bin/aapt2}"
    apksigner="${PORT_SYSTEMUI_APKSIGNER:-otatools/bin/apksigner}"
    [[ -x "${aapt2}" ]] || { echo "Missing aapt2: ${aapt2}" >&2; return 1; }
    overlay_root="${images_root}/system_ext/overlay"
    target="${overlay_root}/ColorOSSystemUIColorFix.apk"
    private_tmp="$(mktemp -d "${TMPDIR:-/tmp}/systemui-colors.XXXXXX")" || return 1
    cleanup_systemui_colors() {
        local resolved temp_root
        resolved="$(cd "${private_tmp}" && pwd -P)" || return
        temp_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)" || return
        case "${resolved}" in
            "${temp_root}"/systemui-colors.*) rm -rf -- "${resolved}" ;;
            *) echo "Refusing to remove unexpected temp path: ${resolved}" >&2 ;;
        esac
    }
    trap cleanup_systemui_colors EXIT
    python3 bin/systemui_color_overlay.py --systemui "${systemui}" --framework "${framework}" \
        --aapt2 "${aapt2}" --output-dir "${private_tmp}/source" \
        --overlay-config "${overlay_root}/config/config.xml" || return 1
    if [[ ! -f "${private_tmp}/source/AndroidManifest.xml" ]]; then
        # Remove only our generated overlay if a new donor no longer needs it.
        rm -f -- "${target}"
        return $?
    fi
    for tool in "${apksigner}" otatools/key/testkey.pk8 otatools/key/testkey.x509.pem; do
        [[ -f "${tool}" ]] || { echo "Missing overlay signing tool/material: ${tool}" >&2; return 1; }
    done
    "${aapt2}" compile --dir "${private_tmp}/source/res" -o "${private_tmp}/compiled.zip" || return 1
    "${aapt2}" link -o "${private_tmp}/unsigned.apk" \
        --manifest "${private_tmp}/source/AndroidManifest.xml" -I "${framework}" \
        --auto-add-overlay --no-resource-deduping --no-resource-removal "${private_tmp}/compiled.zip" || return 1
    "${apksigner}" sign --in "${private_tmp}/unsigned.apk" --out "${private_tmp}/signed.apk" \
        --key otatools/key/testkey.pk8 --cert otatools/key/testkey.x509.pem \
        --min-sdk-version 28 --v1-signing-enabled false --v2-signing-enabled true \
        --v3-signing-enabled true || return 1
    "${apksigner}" verify --verbose "${private_tmp}/signed.apk" || return 1
    mkdir -p "${overlay_root}" || return 1
    # Stage on the destination filesystem, then rename after successful signing.
    cp -f -- "${private_tmp}/signed.apk" "${target}.new" || return 1
    chmod 0644 "${target}.new" || return 1
    mv -f -- "${target}.new" "${target}" || return 1
    for contexts in "${images_root}/config/system_ext_file_contexts" \
                    "${images_root}/system_ext/etc/selinux/system_ext_file_contexts"; do
        [[ -f "${contexts}" ]] || continue
        local rule='/system_ext/overlay/ColorOSSystemUIColorFix\.apk u:object_r:vendor_overlay_file:s0'
        grep -qxF "${rule}" "${contexts}" || printf '\n%s\n' "${rule}" >> "${contexts}" || return 1
    done
    green "SystemUI 颜色引用兼容修复已生成" "SystemUI color-reference compatibility overlay staged"
)
