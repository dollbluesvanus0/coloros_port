#!/bin/bash

# ColorOS_port project

# For A-only and V/A-B (not tested) Devices

# Based on Android 14 

# Test Base ROM: OnePlus 8T (ColorOS_14.0.0.600)

# Test Port ROM: OnePlus 12 (ColorOS_14.0.0.810), OnePlus ACE3V(ColorOS_14.0.1.621) Realme GT Neo5 240W(RMX3708_14.0.0.800)

build_user="Bruce Teng"
build_host=$(hostname)

# Resolve every path relative to this checkout.  The original script used the
# caller's working directory, so invoking it from another directory silently
# selected the wrong tools/configuration and could clean unrelated files.
PORT_CALLER_CWD="$(pwd -P)"
PORT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
export PORT_PROJECT_ROOT="${PORT_ROOT}"

usage() {
    printf '%s\n' 'Usage: ./port.sh [--clean] <baserom> <portrom> [portrom2] [portparts]' >&2
}

FORCE_CLEAN=0
_port_args=()
for _port_arg in "$@"; do
    case "${_port_arg}" in
        --clean) FORCE_CLEAN=1 ;;
        -h|--help) usage; exit 0 ;;
        --*) usage; printf 'Unknown option: %s\n' "${_port_arg}" >&2; exit 2 ;;
        *) _port_args+=("${_port_arg}") ;;
    esac
done
set -- "${_port_args[@]}"
if [[ $# -lt 2 || $# -gt 4 ]]; then
    usage
    exit 2
fi

# Normalize local ROM paths before changing directory; URL arguments remain
# untouched and are downloaded into the repository root below.
_port_normalized=("$@")
for _port_idx in 0 1 2; do
    [[ ${_port_idx} -lt ${#_port_normalized[@]} ]] || break
    _port_value="${_port_normalized[${_port_idx}]}"
    case "${_port_value}" in
        http://*|https://*|/*) ;;
        *) _port_normalized[${_port_idx}]="${PORT_CALLER_CWD}/${_port_value}" ;;
    esac
done
set -- "${_port_normalized[@]}"

cd "${PORT_ROOT}" || exit 1
mkdir -p "${PORT_ROOT}/build"
work_dir="${PORT_ROOT}"
arch="$(uname -m)"
[[ "${arch}" == "arm64" ]] && arch="aarch64"
tools_dir="${PORT_ROOT}/bin/$(uname)/${arch}"
export PATH="${tools_dir}:${PORT_ROOT}/otatools/bin:${PATH}"

# Import functions from the remote repository's original root location.
# functions.sh now contains the optimized helpers while retaining the legacy
# names consumed by this monolithic script.
source "${PORT_ROOT}/functions.sh" || exit 1

PORT_LOG_FILE="${PORT_ROOT}/build/port.log"
export PORT_LOG_FILE
PORT_LOCK_DIR="${PORT_ROOT}/build/.port.lock"
if ! mkdir "${PORT_LOCK_DIR}" 2>/dev/null; then
    error "已有另一个移植任务正在运行" "another port task is already running"
    exit 1
fi
printf '%s\n' "$$" > "${PORT_LOCK_DIR}/pid"
_port_cleanup() {
    local rc=$?
    port_wait_workers
    rm -rf -- "${PORT_LOCK_DIR}"
    exit "${rc}"
}
trap _port_cleanup EXIT
trap 'error "脚本被中断，停止以避免继续修改产物" "Script interrupted; stopping safely"; exit 130' INT TERM

check unzip aria2c 7z zip java python3 zstd bc xmlstarlet jq

# Parse only active key=value lines; do not source port_config as shell code.
port_config_get() {
    local key="$1"
    local default_value="${2:-}"
    local value
    value="$(awk -F= -v key="${key}" '
        /^[[:space:]]*#/ || index($0, "=") == 0 { next }
        {
            lhs=$1; sub(/^[[:space:]]+/, "", lhs); sub(/[[:space:]]+$/, "", lhs)
            if (lhs == key) { value=substr($0, index($0, "=")+1); sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); print value; exit }
        }
    ' "${PORT_ROOT}/bin/port_config" 2>/dev/null)"
    [[ -n "${value}" ]] && printf '%s\n' "${value}" || printf '%s\n' "${default_value}"
}

# Values are intentionally explicit and safe by default.  In particular,
# KernelSU must never be enabled merely because a checked-in config line was
# copied from an older development tree.
port_partition="$(port_config_get partition_to_port 'system,system_ext,product,my_product,my_engineering,my_stock,my_heytap,my_carrier,my_region,my_bigball,my_manifest,my_company,my_preload')"
super_list="$(port_config_get possible_super_list 'system system_ext vendor product my_product odm my_engineering vendor_dlkm system_dlkm my_stock my_heytap my_carrier my_region my_bigball my_manifest my_company my_preload')"
repackext4="$(port_config_get repack_with_ext4 false)"
super_extended="$(port_config_get super_extended false)"
pack_with_dsu="$(port_config_get pack_with_dsu false)"
pack_method="${PACK_METHOD:-$(port_config_get pack_method stock)}"
PORT_PACK_JOBS="${PORT_PACK_JOBS:-$(port_config_get pack_jobs auto)}"
export PORT_PACK_JOBS
port_pack_job_count "$(port_cpu_count)" >/dev/null || exit 2
PORT_PATCH_JOBS="${PORT_PATCH_JOBS:-$(port_config_get patch_jobs auto)}"
export PORT_PATCH_JOBS
port_patch_job_count "$(port_cpu_count)" >/dev/null || exit 2
ota_engine="${PORT_OTA_ENGINE:-$(port_config_get ota_engine auto)}"
ota_engine="$(_port::lower "${ota_engine}")"
case "${ota_engine}" in
    auto|rust|delta|stock) ;;
    *)
        error "ota_engine 必须为 auto、rust、delta 或 stock" "ota_engine must be auto, rust, delta, or stock"
        exit 2
        ;;
esac
export PORT_OTA_ENGINE="${ota_engine}"
payload_compression="${PORT_PAYLOAD_COMPRESSION:-$(port_config_get payload_compression fast-xz)}"
payload_compression="$(_port::lower "${payload_compression}")"
case "${payload_compression}" in
    fast-xz|xz|bz2|none) ;;
    *)
        error "payload_compression 必须为 fast-xz、xz、bz2 或 none" "payload_compression must be fast-xz, xz, bz2, or none"
        exit 2
        ;;
esac
export PORT_PAYLOAD_COMPRESSION="${payload_compression}"
_norm_pack_method="$(printf '%s' "${pack_method}" | tr '[:upper:]' '[:lower:]')"
if [[ "${_norm_pack_method}" == "fastboot" ]]; then
    pack_method="fastboot"
    check unix2dos
    green "打包方式: Fastboot 线刷包" "Package format: Fastboot flashable package"
elif [[ "${_norm_pack_method}" == "ota" || "${_norm_pack_method}" == "stock" ]]; then
    pack_method="stock"
    green "打包方式: OTA 升级包 (payload.bin)" "Package format: OTA update package (payload.bin)"
else
    error "pack_method 必须为 ota 或 fastboot" "pack_method must be ota or fastboot"
    exit 2
fi
ddr_type="$(port_config_get ddr_type '')"
reusabe_partition_list="$(port_config_get reusabe_partition_list '')"
remove_data_encryption="$(port_config_get remove_data_encryption false)"
enable_ksu="$(port_config_get enable_ksu false)"
ksu_repo_owner="$(port_config_get ksu_repo_owner tiann)"
ksu_repo_name="$(port_config_get ksu_repo_name KernelSU)"
install_via="$(_port::lower "$(port_config_get install_via true)")"
install_play_store="$(_port::lower "$(port_config_get install_play_store true)")"
install_kernelsu="$(_port::lower "$(port_config_get install_kernelsu true)")"
for _app_flag_name in install_via install_play_store install_kernelsu; do
    _app_flag_val="${!_app_flag_name}"
    if [[ "${_app_flag_val}" != true && "${_app_flag_val}" != false ]]; then
        error "${_app_flag_name} 必须为 true 或 false" "${_app_flag_name} must be true or false"
        exit 2
    fi
done
if [[ "${repackext4}" == true ]]; then
    pack_type=EXT
elif [[ "${repackext4}" == false ]]; then
    pack_type=EROFS
else
    error "repack_with_ext4 必须为 true 或 false" "repack_with_ext4 must be true or false"
    exit 2
fi
if [[ "${enable_ksu}" != true && "${enable_ksu}" != false ]]; then
    error "enable_ksu 必须为 true 或 false" "enable_ksu must be true or false"
    exit 2
fi

# 底包和移植包为外部参数传入
baserom="${1:-}"
portrom="${2:-}"
portrom2="${3:-}"
portparts="${4:-}"

port_resolve_input() {
    local label="$1"
    local value="$2"
    local downloaded_name
    local downloaded_path
    if [[ "${value}" == http://* || "${value}" == https://* ]]; then
        blue "${label}为一个链接，正在尝试下载" "${label} URL detected, downloading"
        downloaded_name="$(basename "${value%%\?*}")"
        [[ -n "${downloaded_name}" && "${downloaded_name}" != "." && "${downloaded_name}" != "/" && "${downloaded_name}" != ".." ]] || {
            error "${label}链接没有有效文件名" "${label} URL has no valid file name"
            return 1
        }
        downloaded_path="${PORT_ROOT}/${downloaded_name}"
        if [[ ! -s "${downloaded_path}" || -e "${downloaded_path}.aria2" ]]; then
            port_download_rom "${value}" "${downloaded_path}" || {
                error "下载错误" "Download error"
                return 1
            }
        fi
        [[ -s "${downloaded_path}" ]] || {
            error "下载错误" "Download error"
            return 1
        }
        PORT_RESOLVED_INPUT="${downloaded_path}"
    elif [[ -f "${value}" ]]; then
        PORT_RESOLVED_INPUT="${value}"
    else
        error "${label}参数错误" "${label}: Invalid parameter"
        return 1
    fi
    green "${label}: ${PORT_RESOLVED_INPUT}" "${label}: ${PORT_RESOLVED_INPUT}"
}

port_resolve_input "底包" "${baserom}" || exit 1
baserom="${PORT_RESOLVED_INPUT}"
port_resolve_input "移植包" "${portrom}" || exit 1
portrom="${PORT_RESOLVED_INPUT}"
if [[ -n "${portrom2}" ]]; then
    port_resolve_input "第二移植包" "${portrom2}" || exit 1
    portrom2="${PORT_RESOLVED_INPUT}"
fi

# Fingerprints are used for safe extraction-cache reuse and are deliberately
# computed after any URL download has completed.
baserom_hash="$(port_rom_fingerprint "${baserom}")" || {
    error "无法计算底包 SHA-256" "Unable to fingerprint BASEROM"
    exit 1
}
portrom_hash="$(port_rom_fingerprint "${portrom}")" || {
    error "无法计算移植包 SHA-256" "Unable to fingerprint PORTROM"
    exit 1
}
portrom2_hash=""
if [[ -n "${portrom2}" ]]; then
    portrom2_hash="$(port_rom_fingerprint "${portrom2}")" || {
        error "无法计算第二移植包 SHA-256" "Unable to fingerprint second PORTROM"
        exit 1
    }
fi

if [ "$(echo $baserom |grep ColorOS_)" != "" ];then
    device_code=$(basename $baserom |cut -d '_' -f 2)
else
    device_code="op8t"
fi

blue "正在检测ROM底包" "Validating BASEROM.."

# 检测底包类型
if unzip -l "${baserom}" | grep -q "payload.bin"; then
    baserom_type="payload"
    oplus_hex_nv_id=$(unzip -p "${baserom}" META-INF/com/android/metadata 2>/dev/null | grep "oplus_hex_nv_id=" | cut -d= -f2)
elif unzip -l "${baserom}" | grep -Eq "br$"; then
    baserom_type="br"
    oplus_hex_nv_id=$(unzip -p "${baserom}" META-INF/com/android/metadata 2>/dev/null | grep "oplus_hex_nv_id=" | cut -d= -f2)
elif unzip -l "${baserom}" | grep -Eq "\.img$"; then
    baserom_type="img"
else
    error "底包中未发现 payload.bin、br 或 img 文件，请使用官方ROM包后重试" \
          "payload.bin / *.br / *.img not found, please use official OTA or fastboot package."
    exit 1
fi

green "检测到底包类型: ${baserom_type}" "Detected base package type: ${baserom_type}"


blue "开始检测ROM移植包" "Validating PORTROM.."

# 检测移植包类型
if unzip -l "${portrom}" | grep -q "payload.bin"; then
    portrom_type="payload"
elif unzip -l "${portrom}" | grep -Eq "\.img$"; then
    portrom_type="img"
else
    error "目标移植包中未发现 payload.bin 或 img 文件，请使用包含 system.img 的官方ROM包作为移植包" \
          "payload.bin or *.img not found, please use an official ROM package containing system.img as PORTROM."
    exit 1
fi

sanitize_build_label() {
    local value="${1:-}"
    value="${value//[^A-Za-z0-9._-]/_}"
    value="${value:0:128}"
    case "${value}" in
        ""|"."|"..") value="rom" ;;
    esac
    printf '%s' "${value}"
}

# 提取版本信息（仅当有 metadata 时）
if unzip -l "${portrom}" | grep -q "META-INF/com/android/metadata"; then
    version_name=$(unzip -p "${portrom}" META-INF/com/android/metadata 2>/dev/null | grep "version_name=" | cut -d= -f2)
    ota_version=$(unzip -p "${portrom}" META-INF/com/android/metadata 2>/dev/null | grep "ota_version=" | cut -d= -f2)
else
    version_name="$(basename "${portrom%.*}")"
    ota_version="V16.0.0"
fi
version_name="$(sanitize_build_label "${version_name}")"

green "ROM初步检测通过，类型: ${portrom_type}" "ROM validation passed. Type: ${portrom_type}"
[[ -n "${version_name}" ]] && echo "版本名: ${version_name}"


mix_port=false
if [[ -n "${portrom2}" ]]; then
    mix_port=true
fi

if [[ -n "${portparts}" ]]; then
    read -r -a mix_port_part <<< "${portparts}"
else
    mix_port_part=("my_stock" "my_region" "my_manifest" "my_product")
fi

if [[ $mix_port == true ]];then
    blue "混合移植包模式"
    blue "开始检测第二个移植包" "Validating PORTROM.."
    if unzip -l "${portrom2}" | grep -q "payload.bin"; then
        green "第二个ROM初步检测通过" "ROM validation passed."
        portrom2_type="payload"
        version_name2=$(unzip -p "${portrom2}" META-INF/com/android/metadata 2>/dev/null | grep "version_name=" | cut -d = -f2)
        [[ -n "${version_name2}" ]] || version_name2="$(basename "${portrom2%.*}")"
    elif unzip -l "${portrom2}" | grep -Eq "\.img$"; then
        portrom2_type="img"
        version_name2="$(basename "${portrom2%.*}")"
    else
        error "目标移植包中未发现 payload.bin 或 img 文件，请使用包含 system.img 的官方ROM包作为移植包" \
          "payload.bin or *.img not found, please use an official ROM package containing system.img as PORTROM."
        exit 1
    fi
    version_name2="$(sanitize_build_label "${version_name2}")"
fi
green "ROM初步检测通过" "ROM validation passed."

blue "正在清理文件" "Cleaning up.."

if [[ "${FORCE_CLEAN}" -eq 1 ]]; then
    # --clean is deliberately scoped to the project cache; never broaden it
    # to the caller's working directory or to downloaded input archives.
    if [[ -d "${PORT_ROOT}/build/cache/roms" ]]; then
        find "${PORT_ROOT}/build/cache/roms" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    fi
fi
rm -rf app
rm -rf tmp
rm -rf config
rm -rf build/baserom/
rm -rf build/portrom/
find . -type d -name 'ColorOS_*' |xargs rm -rf

green "文件清理完毕" "Files cleaned up."
mkdir -p build/baserom/images/

mkdir -p build/portrom/images/

mkdir tmp 
export TMPDIR=$work_dir/tmp/
# Content-addressed base-image cache.  BR packages also carry firmware and
# other non-image entries, so only payload/img inputs use the image-only cache;
# BR extraction keeps its complete legacy path below.
baserom_cache_path=""
baserom_cache_hit=false
if [[ "${baserom_type}" != "br" ]]; then
    baserom_cache_path="$(port_cache_dir baserom "${baserom_hash}")"
    if port_cache_has_images "${baserom_cache_path}" "system,product,system_ext,my_product,my_manifest"; then
        baserom_cache_hit=true
        mkdir -p build/baserom/images/
        port_copy_images "${baserom_cache_path}" build/baserom/images || exit 1
        green "底包缓存命中，跳过重复解包" "BASEROM cache hit; skipping extraction"
    fi
fi
# ===== 提取底包 =====
if [[ "${baserom_cache_hit}" == true ]]; then
    :
elif [[ ${baserom_type} == 'payload' ]]; then
    blue "正在提取底包 [payload.bin]" "Extracting files from BASEROM [payload.bin]"   
    payload-extract extract -o build/baserom/images/ "${baserom}" || {
        error "底包 payload 提取失败" "Failed to extract BASEROM payload"
        exit 1
    }
    green "底包 [payload.bin] 提取完毕" "[payload.bin] extracted."

elif [[ ${baserom_type} == 'br' ]]; then
    blue "正在提取底包 [new.dat.br]" "Extracting files from BASEROM [*.new.dat.br]"
    unzip -qo "${baserom}" -d build/baserom || {
        error "解压底包 [new.dat.br]时出错" "Extracting [new.dat.br] error"
        exit 1
    }
    green "底包 [new.dat.br] 解压完毕" "[new.dat.br] extracted."

    blue "开始分解底包 [new.dat.br]" "Unpacking BASEROM [new.dat.br]"
    # 修复带数字的文件名问题
    for file in build/baserom/*; do
        filename=$(basename -- "$file")
        extension="${filename##*.}"
        name="${filename%.*}"

        if [[ $name =~ [0-9] ]]; then
            new_name=$(echo "$name" | sed 's/[0-9]\+\(\.[^0-9]\+\)/\1/g' | sed 's/\.\./\./g')
            mv -f "$file" "build/baserom/${new_name}.${extension}"
        fi
    done

    # 转换为 .img
    for i in ${super_list}; do 
        if [[ -f build/baserom/${i}.new.dat.br ]]; then
            "${tools_dir}/brotli" -d "build/baserom/${i}.new.dat.br" >/dev/null 2>&1 || {
                error "${i}.new.dat.br 解压失败" "Failed to decompress ${i}.new.dat.br"
                exit 1
            }
            python3 "${tools_dir}/sdat2img.py" \
                build/baserom/${i}.transfer.list \
                build/baserom/${i}.new.dat \
                build/baserom/images/${i}.img >/dev/null 2>&1 || {
                error "${i} 分区转换失败" "Failed to convert ${i} to an image"
                exit 1
            }
            rm -rf build/baserom/${i}.new.dat* build/baserom/${i}.transfer.list build/baserom/${i}.patch.*
        fi
    done
    green "底包 [new.dat.br] 分解完毕" "[new.dat.br] unpack complete."

elif [[ ${baserom_type} == 'img' ]]; then
    blue "检测到底包类型为 [img]" "Extracting BASEROM containing .img files"
    mkdir -p build/baserom/images/
    unzip -qo "${baserom}" -d build/baserom/tmp/ || {
        error "解压底包时出错" "Extracting BASEROM error"
        exit 1
    }
    # 移动所有 img 文件
    find build/baserom/tmp/ -type f -name "*.img" -exec mv -f {} build/baserom/images/ \;
    rm -rf build/baserom/tmp/
    green "底包 [*.img] 提取完毕" "[*.img] extracted."
else
    error "未知底包类型: ${baserom_type}" "Unknown base package type: ${baserom_type}"
    exit 1
fi

if [[ "${baserom_cache_hit}" != true && "${baserom_type}" != "br" ]]; then
    port_cache_store_images "${baserom_cache_path}" "build/baserom/images" \
        "${baserom_hash}" baserom "${device_code}" || \
        yellow "无法写入底包缓存，继续使用当前解包结果" "Unable to write base cache; continuing"
fi


# ===== 提取移植包 =====
# A cache entry is keyed by the archive digest and may be a full or partial
# hit.  Partial hits copy the known images first and extract only the missing
# partitions, which keeps large payload extraction resumable.
port_cache_path="$(port_cache_dir portrom "${portrom_hash}")"
portrom_cache_dir="${port_cache_path}/"
port_version_cache_valid=false
port_cache_hit=""
port_cache_source=""
if [[ -n "${version_name}" && -d "build/${version_name}" && \
      -f "build/${version_name}/.source.sha256" && \
      "$(< "build/${version_name}/.source.sha256")" == "${portrom_hash}" ]]; then
    if port_cache_has_images "build/${version_name}" "${port_partition}"; then
        port_version_cache_valid=true
        port_cache_hit=full
        port_cache_source="build/${version_name}"
    else
        yellow "移植包缓存缺少所需分区，重新提取" "Port cache is incomplete; extracting again"
        rm -rf -- "build/${version_name}"
    fi
elif [[ -n "${version_name}" && -d "build/${version_name}" ]]; then
    yellow "移植包缓存来源已变化，重新提取" "Port cache source digest changed; extracting again"
    rm -rf -- "build/${version_name}"
fi
if [[ "${port_version_cache_valid}" != true ]] && port_cache_has_images "${port_cache_path}" "${port_partition}"; then
    port_cache_hit=full
    port_cache_source="${port_cache_path}"
fi

if [[ "${port_cache_hit}" == full ]]; then
    blue "检测到按 SHA-256 验证的移植包缓存，跳过重复解包" "SHA-256 verified port cache hit; skipping extraction"
    mkdir -p "build/${version_name}" build/portrom/images/
    if [[ "${port_cache_source}" != "build/${version_name}" ]]; then
        port_copy_images "${port_cache_source}" "build/${version_name}" || exit 1
    fi
    port_copy_images "${port_cache_source}" build/portrom/images || exit 1
    printf '%s\n' "${portrom_hash}" > "build/${version_name}/.source.sha256"
else
    mkdir -p "build/${version_name}" build/portrom/images/
    extract_parts="${port_partition}"
    if [[ -d "${port_cache_path}" ]]; then
        IFS=',' read -r -a _requested_parts <<< "${port_partition}"
        extract_parts=""
        for _requested_part in "${_requested_parts[@]}"; do
            [[ -n "${_requested_part}" ]] || continue
            if [[ -s "${port_cache_path}/${_requested_part}.img" ]]; then
                port_copy_image "${port_cache_path}/${_requested_part}.img" "build/${version_name}/${_requested_part}.img" || exit 1
                port_copy_image "${port_cache_path}/${_requested_part}.img" "build/portrom/images/${_requested_part}.img" || exit 1
            else
                extract_parts+="${_requested_part},"
            fi
        done
        extract_parts="${extract_parts%,}"
        [[ -n "${extract_parts}" ]] && blue "移植包缓存部分命中，提取缺失分区 [${extract_parts}]" "PORTROM partial cache hit; extracting [${extract_parts}]"
    fi

    if [[ ${portrom_type} == 'payload' ]]; then
        if [[ -n "${extract_parts}" ]]; then
            # payload-extract rejects names that are not present.  Filter a
            # partial request against the payload manifest first so optional
            # empty partitions remain available to the later pack stage.
            _payload_available="$(payload-extract list "${portrom}" 2>/dev/null | tail -n +3 | awk '{print $1}')"
            _payload_extract_parts=""
            IFS=',' read -r -a _payload_requested <<< "${extract_parts}"
            for _payload_part in "${_payload_requested[@]}"; do
                printf '%s\n' "${_payload_available}" | grep -qx "${_payload_part}" && _payload_extract_parts+="${_payload_part},"
            done
            _payload_extract_parts="${_payload_extract_parts%,}"
            if [[ -n "${_payload_extract_parts}" ]]; then
                blue "正在提取移植包 [payload.bin]" "Extracting PORTROM [payload.bin]"
                payload-extract extract -p "${_payload_extract_parts}" -o "build/${version_name}/" "${portrom}" || exit 1
                port_copy_images "build/${version_name}" build/portrom/images || exit 1
            else
                blue "缺失分区均不存在于 payload，跳过解包" "Missing partitions are not in payload; skipping extraction"
            fi
        fi
        green "移植包 [payload.bin] 提取完毕" "[payload.bin] extracted."
    elif [[ ${portrom_type} == 'img' ]]; then
        if [[ -n "${extract_parts}" ]]; then
            blue "检测到移植包类型为 [img]" "Extracting PORTROM containing .img files"
            IFS=',' read -r -a _requested_parts <<< "${extract_parts}"
            declare -a unzip_targets=()
            while IFS= read -r _zip_entry; do
                _zip_base="${_zip_entry##*/}"
                for _requested_part in "${_requested_parts[@]}"; do
                    [[ "${_zip_base}" == "${_requested_part}.img" ||
                       "${_zip_base}" == "${_requested_part}_a.img" ||
                       "${_zip_base}" == "${_requested_part}_b.img" ]] && unzip_targets+=("${_zip_entry}")
                done
            done < <(unzip -Z1 "${portrom}" 2>/dev/null)
            if [[ ${#unzip_targets[@]} -eq 0 ]]; then
                error "移植包中未找到所需分区镜像" "No requested partition images found in PORTROM"
                exit 1
            fi
            if ! unzip -qo "${portrom}" "${unzip_targets[@]}" -d "build/${version_name}/"; then
                error "解压指定 img 文件失败，请检查移植包内容" "Failed to extract selected images from PORTROM"
                exit 1
            fi
            while IFS= read -r -d '' _image; do
                port_copy_image "${_image}" "build/portrom/images/${_image##*/}" || exit 1
            done < <(find "build/${version_name}/" -type f -name '*.img' -print0)
            green "移植包 [*.img] 提取完毕" "[*.img] extracted."
        fi
    else
        error "未知移植包类型: ${portrom_type}" "Unknown port package type: ${portrom_type}"
        exit 1
    fi
    printf '%s\n' "${portrom_hash}" > "build/${version_name}/.source.sha256"
    port_cache_store_images "${port_cache_path}" "build/${version_name}" "${portrom_hash}" portrom "${version_name}" || \
        yellow "无法写入移植包缓存，继续使用当前解包结果" "Unable to write port cache; continuing with extracted files"
fi

port_version2_cache_valid=false
port_cache_path2=""
portrom2_cache_dir=""
if [[ -n "${version_name2}" ]]; then
    port_cache_path2="$(port_cache_dir portrom2 "${portrom2_hash}")"
    portrom2_cache_dir="${port_cache_path2}/"
    port_cache2_hit=""
    port_cache2_source=""
    if [[ -n "${version_name2}" && -d "build/${version_name2}" && \
          -f "build/${version_name2}/.source.sha256" && \
          "$(< "build/${version_name2}/.source.sha256")" == "${portrom2_hash}" ]] && \
       port_cache_has_images "build/${version_name2}" "$(IFS=','; echo "${mix_port_part[*]}")"; then
        port_cache2_hit=full
        port_cache2_source="build/${version_name2}"
    elif [[ -d "${port_cache_path2}" ]] && \
         port_cache_has_images "${port_cache_path2}" "$(IFS=','; echo "${mix_port_part[*]}")"; then
        port_cache2_hit=full
        port_cache2_source="${port_cache_path2}"
    fi

    if [[ "${port_cache2_hit}" == full ]]; then
        blue "检测到按 SHA-256 验证的第二移植包缓存，跳过重复解包" "SHA-256 verified second port cache hit"
        mkdir -p "build/${version_name2}" build/portrom/images/
        for _mix_part in "${mix_port_part[@]}"; do
            if [[ "${port_cache2_source}" != "build/${version_name2}" ]]; then
                port_copy_image "${port_cache2_source}/${_mix_part}.img" "build/${version_name2}/${_mix_part}.img" || exit 1
            fi
            port_copy_image "${port_cache2_source}/${_mix_part}.img" "build/portrom/images/${_mix_part}.img" || exit 1
        done
        printf '%s\n' "${portrom2_hash}" > "build/${version_name2}/.source.sha256"
        port_version2_cache_valid=true
    else
        mkdir -p "build/${version_name2}" build/portrom/images/
        extract2_parts=""
        for _mix_part in "${mix_port_part[@]}"; do
            [[ -n "${_mix_part}" ]] || continue
            if [[ -s "${port_cache_path2}/${_mix_part}.img" ]]; then
                port_copy_image "${port_cache_path2}/${_mix_part}.img" "build/${version_name2}/${_mix_part}.img" || exit 1
                port_copy_image "${port_cache_path2}/${_mix_part}.img" "build/portrom/images/${_mix_part}.img" || exit 1
            else
                extract2_parts+="${_mix_part},"
            fi
        done
        extract2_parts="${extract2_parts%,}"
        if [[ ${portrom2_type} == 'payload' ]]; then
            if [[ -n "${extract2_parts}" ]]; then
                _payload2_available="$(payload-extract list "${portrom2}" 2>/dev/null | tail -n +3 | awk '{print $1}')"
                _payload2_extract_parts=""
                IFS=',' read -r -a _payload2_requested <<< "${extract2_parts}"
                for _payload2_part in "${_payload2_requested[@]}"; do
                    printf '%s\n' "${_payload2_available}" | grep -qx "${_payload2_part}" && _payload2_extract_parts+="${_payload2_part},"
                done
                _payload2_extract_parts="${_payload2_extract_parts%,}"
                if [[ -n "${_payload2_extract_parts}" ]]; then
                    payload-extract extract -p "${_payload2_extract_parts}" -o "build/${version_name2}/" "${portrom2}" || exit 1
                    for _mix_part in "${mix_port_part[@]}"; do
                        [[ -s "build/${version_name2}/${_mix_part}.img" ]] || continue
                        port_copy_image "build/${version_name2}/${_mix_part}.img" "build/portrom/images/${_mix_part}.img" || exit 1
                    done
                fi
            fi
        elif [[ ${portrom2_type} == 'img' && -n "${extract2_parts}" ]]; then
            IFS=',' read -r -a _mix_requested <<< "${extract2_parts}"
            declare -a unzip_targets2=()
            while IFS= read -r _zip_entry; do
                _zip_base="${_zip_entry##*/}"
                for _mix_part in "${_mix_requested[@]}"; do
                    [[ "${_zip_base}" == "${_mix_part}.img" ||
                       "${_zip_base}" == "${_mix_part}_a.img" ||
                       "${_zip_base}" == "${_mix_part}_b.img" ]] && unzip_targets2+=("${_zip_entry}")
                done
            done < <(unzip -Z1 "${portrom2}" 2>/dev/null)
            if [[ ${#unzip_targets2[@]} -gt 0 ]]; then
                unzip -qo "${portrom2}" "${unzip_targets2[@]}" -d "build/${version_name2}/" || exit 1
                while IFS= read -r -d '' _image; do
                    port_copy_image "${_image}" "build/portrom/images/${_image##*/}" || exit 1
                done < <(find "build/${version_name2}/" -type f -name '*.img' -print0)
            fi
        fi
        printf '%s\n' "${portrom2_hash}" > "build/${version_name2}/.source.sha256"
        port_cache_store_images "${port_cache_path2}" "build/${version_name2}" "${portrom2_hash}" portrom2 "${version_name2}" || \
            yellow "无法写入第二移植包缓存，继续使用当前解包结果" "Unable to write second port cache; continuing"
    fi
fi

if [[ -n ${version_name} ]] && [[ -n ${version_name2} ]];then
    app_patch_folder=${version_name2}
elif [[ -n ${version_name} ]];then
    app_patch_folder=${version_name}
fi

mkdir -p build/baserom/images/config build/portrom/images/config || exit 1
_extract_jobs="$(port_extract_job_count "$(port_cpu_count)")" || exit 2
blue "并行提取底包分区 (${_extract_jobs} 线程)" "Extracting BASEROM partitions in parallel (${_extract_jobs} job(s))"
port_run_jobs "${_extract_jobs}" "${work_dir}/build/logs/extract-base" _port::extract_baserom_worker \
    system product system_ext my_product my_manifest \
    vendor odm my_company my_preload system_dlkm vendor_dlkm my_engineering || {
    error "底包分区提取失败" "BASEROM partition extraction failed"
    exit 1
}

if [ ! -d build/portrom/images/system_dlkm ];then
        super_list="system system_ext vendor product my_product odm my_engineering my_stock my_heytap my_carrier my_region my_bigball my_manifest my_company my_preload"
fi
# Extract the partitions list that need to pack into the super.img
#super_list=$(sed '/^#/d;/^\//d;/overlay/d;/^$/d;/\^loop/d' build/portrom/images/vendor/etc/fstab.qcom \
#                | awk '{ print $1}' | sort | uniq)

# 分解镜像
green "开始提取逻辑分区镜像" "Starting extract portrom partition from img"
read -r -a _port_super_parts <<< "${super_list}"
port_run_jobs "${_extract_jobs}" "${work_dir}/build/logs/extract-port" _port::extract_portrom_part \
    "${_port_super_parts[@]}" || {
    error "逻辑分区提取失败" "Partition extraction failed"
    exit 1
}
rm -rf config

run_rom_ops debloat build/portrom/images bin/donor-debloat.txt
_debloat_rc=$?
if [[ ${_debloat_rc} -eq 127 ]]; then
    python3 bin/debloat_rom.py build/portrom/images || exit 1
elif [[ ${_debloat_rc} -ne 0 ]]; then
    exit "${_debloat_rc}"
fi

# Actions uses a fresh checkout: discard duplicate extraction caches once all
# input images are unpacked. Local runs keep their reusable caches by default.
if [[ "${PORT_LOW_DISK:-false}" == true ]]; then
    rm -rf -- build/cache/roms build/ci-inputs
    for cache_name in "${version_name}" "${version_name2:-}"; do
        [[ -n "${cache_name}" && "${cache_name}" != */* && "${cache_name}" != .* ]] || continue
        [[ -d "build/${cache_name}" ]] || continue
        find "build/${cache_name}" -maxdepth 1 -type f -name '*.img' -delete
    done
    df -h .
fi

blue "正在获取ROM参数" "Fetching ROM build prop."

# Detect tablet mode before changing the port properties.  A base/port
# mismatch is recorded for diagnostics so device-specific overlays can choose
# not to cross tablet and phone resource sets accidentally.
stock_build_characteristics=""
if [[ -f build/baserom/images/my_product/build.prop ]]; then
    stock_build_characteristics=$(grep -m1 '^ro\.build\.characteristics=' \
        build/baserom/images/my_product/build.prop | cut -d= -f2)
fi
if [[ -z "${stock_build_characteristics}" && -f build/baserom/images/product/build.prop ]]; then
    stock_build_characteristics=$(grep -m1 '^ro\.build\.characteristics=' \
        build/baserom/images/product/build.prop | cut -d= -f2)
fi
port_build_characteristics=""
if [[ -f build/portrom/images/my_product/build.prop ]]; then
    port_build_characteristics=$(grep -m1 '^ro\.build\.characteristics=' \
        build/portrom/images/my_product/build.prop | cut -d= -f2)
fi
if [[ -z "${port_build_characteristics}" && -f build/portrom/images/product/build.prop ]]; then
    port_build_characteristics=$(grep -m1 '^ro\.build\.characteristics=' \
        build/portrom/images/product/build.prop | cut -d= -f2)
fi
stock_is_tablet=false
port_is_tablet=false
[[ "${stock_build_characteristics}" == tablet ]] && stock_is_tablet=true
[[ "${port_build_characteristics}" == tablet ]] && port_is_tablet=true
tablet_mode_cross=false
[[ "${stock_is_tablet}" != "${port_is_tablet}" ]] && tablet_mode_cross=true
green "平板属性 - 底包: [${stock_is_tablet}] 移植包: [${port_is_tablet}] 跨模式: [${tablet_mode_cross}]" \
      "Tablet - Stock: [${stock_is_tablet}] Port: [${port_is_tablet}] Cross: [${tablet_mode_cross}]"

# 安卓版本
base_android_version=$(< build/baserom/images/system/system/build.prop grep "ro.build.version.release" |awk 'NR==1' |cut -d '=' -f 2)
port_android_version=$(< build/portrom/images/system/system/build.prop grep "ro.build.version.release" |awk 'NR==1' |cut -d '=' -f 2)
green "安卓版本: 底包为[Android ${base_android_version}], 移植包为 [Android ${port_android_version}]" "Android Version: BASEROM:[Android ${base_android_version}], PORTROM [Android ${port_android_version}]"

# SDK版本
base_android_sdk=$(< build/baserom/images/system/system/build.prop grep "ro.system.build.version.sdk" |awk 'NR==1' |cut -d '=' -f 2)
port_android_sdk=$(< build/portrom/images/system/system/build.prop grep "ro.system.build.version.sdk" |awk 'NR==1' |cut -d '=' -f 2)
green "SDK 版本: 底包为 [SDK ${base_android_sdk}], 移植包为 [SDK ${port_android_sdk}]" "SDK Verson: BASEROM: [SDK ${base_android_sdk}], PORTROM: [SDK ${port_android_sdk}]"

# ROM版本
base_rom_version=$(<  build/baserom/images/my_manifest/build.prop grep "ro.build.display.ota" | awk 'NR==1' | cut -d '=' -f 2 | cut -d "_" -f 2-)
port_rom_version=$(<  build/portrom/images/my_manifest/build.prop grep "ro.build.display.ota" | awk 'NR==1' | cut -d '=' -f 2 | cut -d "_" -f 2-)
green "ROM 版本: 底包为 [${base_rom_version}], 移植包为 [${port_rom_version}]" "ROM Version: BASEROM: [${base_rom_version}], PORTROM: [${port_rom_version}] "

#ColorOS版本号获取

base_device_code=$(< build/baserom/images/my_manifest/build.prop grep "ro.oplus.version.my_manifest" | awk 'NR==1' | cut -d '=' -f 2 | cut -d "_" -f 1)
port_device_code=$(< build/portrom/images/my_manifest/build.prop grep "ro.oplus.version.my_manifest" | awk 'NR==1' | cut -d '=' -f 2 | cut -d "_" -f 1)

green "机型代号: 底包为 [${base_device_code}], 移植包为 [${port_device_code}]" "Device Code: BASEROM: [${base_device_code}], PORTROM: [${port_device_code}]"
# 代号
base_product_device=$(< build/baserom/images/my_manifest/build.prop grep "ro.product.device" |awk 'NR==1' |cut -d '=' -f 2)
port_product_device=$(< build/portrom/images/my_manifest/build.prop grep "ro.product.device" |awk 'NR==1' |cut -d '=' -f 2)
green "Product机型: 底包为 [${base_product_device}], 移植包为 [${port_product_device}]" "Product Device: BASEROM: [${base_product_device}], PORTROM: [${port_product_device}]"

base_product_name=$(< build/baserom/images/my_manifest/build.prop grep "ro.product.name" |awk 'NR==1' |cut -d '=' -f 2)
port_product_name=$(< build/portrom/images/my_manifest/build.prop grep "ro.product.name" |awk 'NR==1' |cut -d '=' -f 2)
green "Product名称: 底包为 [${base_product_name}], 移植包为 [${port_product_name}]" "Product Name: BASEROM: [${base_product_name}], PORTROM: [${port_product_name}]"

base_product_model=$(< build/baserom/images/my_manifest/build.prop grep "ro.product.model" |awk 'NR==1' |cut -d '=' -f 2)
port_product_model=$(< build/portrom/images/my_manifest/build.prop grep "ro.product.model" |awk 'NR==1' |cut -d '=' -f 2)
green "Product型号: 底包为 [${base_product_model}], 移植包为 [${port_product_model}]" "Product Model: BASEROM: [${base_product_model}], PORTROM: [${port_product_model}]"
if grep -q "ro.vendor.oplus.market.name" build/baserom/images/my_manifest/build.prop;then
    base_market_name=$(< build/baserom/images/my_manifest/build.prop grep "ro.vendor.oplus.market.name" |awk 'NR==1' |cut -d '=' -f 2)
else
    base_market_name=$(< build/portrom/images/odm/build.prop grep "ro.vendor.oplus.market.name" |awk 'NR==1' |cut -d '=' -f 2)
fi

if grep -q "ro.vendor.oplus.market.enname" build/baserom/images/my_manifest/build.prop;then
    base_market_enname=$(< build/baserom/images/my_manifest/build.prop grep "ro.vendor.oplus.market.enname" |awk 'NR==1' |cut -d '=' -f 2)
else
    base_market_enname=$(< build/portrom/images/odm/build.prop grep "ro.vendor.oplus.market.enname" |awk 'NR==1' |cut -d '=' -f 2)
fi

port_market_name=$(grep -r --include="*.prop"  --exclude-dir="odm" "ro.vendor.oplus.market.name" build/portrom/images/ | head -n 1 | awk "NR==1" | cut -d "=" -f2)

green "市场名称: 底包为 [${base_market_name}], 移植包为 [${port_market_name}]" "Market Name: BASEROM: [${base_market_name}], PORTROM: [${port_market_name}]"

base_my_product_type=$(< build/baserom/images/my_product/build.prop grep "ro.oplus.image.my_product.type" |awk 'NR==1' |cut -d '=' -f 2)
port_my_product_type=$(< build/portrom/images/my_product/build.prop grep "ro.oplus.image.my_product.type" |awk 'NR==1' |cut -d '=' -f 2)

green "my_product类型: 底包为 [${base_my_product_type}], 移植包为 [${port_my_product_type}]" "My_Product Type: BASEROM: [${base_my_product_type}], PORTROM: [${port_my_product_type}]"

target_display_id=$(< build/portrom/images/my_manifest/build.prop grep "ro.build.display.id=" |awk 'NR==1' |cut -d '=' -f 2 | sed "s/$port_device_code/$base_device_code/g")

target_display_id_show=$(< build/portrom/images/my_manifest/build.prop grep "ro.build.display.id.show" |awk 'NR==1' |cut -d '=' -f 2 | sed "s/$port_device_code/$base_device_code/g") 

base_vendor_brand=$(< build/baserom/images/my_manifest/build.prop grep "ro.product.vendor.brand" |awk 'NR==1' |cut -d '=' -f 2)
port_vendor_brand=$(< build/portrom/images/my_manifest/build.prop grep "ro.product.vendor.brand" |awk 'NR==1' |cut -d '=' -f 2)

port_ssi_brand=$(< build/portrom/images/system_ext/etc/build.prop grep "ro.oplus.image.system_ext.brand" |awk 'NR==1' |cut -d '=' -f 2)

base_product_first_api_level=$(< build/baserom/images/my_manifest/build.prop grep "ro.product.first_api_level" |awk 'NR==1' |cut -d '=' -f 2)
port_product_first_api_level=$(< build/portrom/images/my_manifest/build.prop grep "ro.product.first_api_level" |awk 'NR==1' |cut -d '=' -f 2)

base_device_family=$(< build/baserom/images/my_product/build.prop grep "ro.build.device_family" |awk 'NR==1' |cut -d '=' -f 2)
target_device_family=$(< build/portrom/images/my_product/build.prop grep "ro.build.device_family" |awk 'NR==1' |cut -d '=' -f 2)

# Security Patch Date
portrom_version_security_patch=$(< build/portrom/images/my_manifest/build.prop grep "ro.build.version.security_patch" |awk 'NR==1' |cut -d '=' -f 2 )
port_oplusrom_version=$(< build/portrom/images/my_product/build.prop grep "ro.build.version.oplusrom.confidential" |awk 'NR==1' |cut -d '=' -f 2 )

port_release_or_codename=$(< build/portrom/images/my_manifest/build.prop grep "ro.build.version.release_or_codename" |awk 'NR==1' |cut -d '=' -f 2)
    
#regionmark=$(< build/portrom/images/my_bigball/etc/region/build.prop grep "ro.vendor.oplus.regionmark" |awk 'NR==1' |cut -d '=' -f 2)
regionmark=$(find build/portrom/images/ -name build.prop -exec grep -m1 "ro.vendor.oplus.regionmark=" {} \; -quit | cut -d '=' -f2)

base_regionmark=$(find build/baserom/images/ -name build.prop -exec grep -m1 "ro.vendor.oplus.regionmark=" {} \; -quit | cut -d '=' -f2)
if [ -z "$base_regionmark" ]; then
  base_regionmark=$(find build/baserom/images/ -name build.prop -exec grep -m1 "ro.oplus.image.my_region.type=" {} \; -quit | cut -d '=' -f2 | cut -d '_' -f1)
fi

base_ab_partitions=$(< build/baserom/images/my_manifest/build.prop grep "ro.product.ab_ota_partitions" |awk 'NR==1' |cut -d '=' -f 2)

vendor_cpu_abilist32=$(< build/portrom/images/vendor/build.prop grep "ro.vendor.product.cpu.abilist32" |awk 'NR==1' |cut -d '=' -f 2 )

base_area=$(grep -r --include="*.prop" --exclude-dir="odm" "ro.oplus.image.system_ext.area" build/baserom/images/ | head -n1 | cut -d "=" -f2 | tr -d '\r')
base_brand=$(grep -r --include="*.prop" --exclude-dir="odm" "ro.oplus.image.system_ext.brand" build/baserom/images/ | head -n1 | cut -d "=" -f2 | tr -d '\r')

baseIsColorOSCN=false
baseIsOOS=false
baseIsRealmeUI=false
if [[ "$base_area" == "domestic" && "$base_brand" != "realme" ]]; then
    baseIsColorOSCN=true
elif [[ "$base_brand" == "realme" ]];then
    baseIsRealmeUI=true
elif [[ "$base_area" == "gdpr" && "$base_brand" == "oneplus" ]]; then
    baseIsOOS=true
fi

port_area=$(grep -r --include="*.prop" --exclude-dir="odm" "ro.oplus.image.system_ext.area" build/portrom/images/ | head -n1 | cut -d "=" -f2 | tr -d '\r')
port_brand=$(grep -r --include="*.prop" --exclude-dir="odm" "ro.oplus.image.system_ext.brand" build/portrom/images/ | head -n1 | cut -d "=" -f2 | tr -d '\r')

portIsColorOSGlobal=false
portIsOOS=false
portIsColorOS=false
portIsRealmeUI=false

port_oplusrom_version=$(get_oplusrom_version)

# ColorOS 16.0.7+ mediaserver expects liboplusbindermonitor.so.  Some older
# base/vendor images still carry the library while the newer port image does
# not, so copy every matching base path into the corresponding port path.
if ver_gte "${port_oplusrom_version}" "16.0.7"; then
    blue "修复ColorOS 16.0.6+ mediaserver库依赖问题" "Fixing mediaserver library dependency for ColorOS 16.0.6+"
    while IFS= read -r -d '' source_lib; do
        relative_path="${source_lib#build/baserom/images/}"
        target_lib="build/portrom/images/${relative_path}"
        mkdir -p "$(dirname "${target_lib}")" || exit 1
        cp -f -- "${source_lib}" "${target_lib}" || exit 1
        green "已从底包复制liboplusbindermonitor.so: ${relative_path}" "Copied liboplusbindermonitor.so: ${relative_path}"
    done < <(find build/baserom/images/ -type f -name "liboplusbindermonitor.so" -print0 2>/dev/null)
fi

if [[ "$port_brand" == "realme" ]];then
    portIsRealmeUI=true
fi

if [[ "$port_area" == "gdpr" && "$port_brand" != "oneplus" ]]; then
    portIsColorOSGlobal=true
elif [[ "$port_area" == "gdpr" && "$port_brand" == "oneplus" ]]; then
    portIsOOS=true
else
    portIsColorOS=true
fi


if grep -q "ro.build.ab_update=true" build/portrom/images/vendor/build.prop;  then
    is_ab_device=true
else
    is_ab_device=false

fi

if [[ ! -f build/portrom/images/system/system/bin/app_process32 && -n "$vendor_cpu_abilist32" ]]; then
    blue "64bit only protrom detected. convert vendor to 64bit-only  "
    sed -i "s/ro.vendor.product.cpu.abilist=.*/ro.vendor.product.cpu.abilist=arm64-v8a/g" build/portrom/images/vendor/build.prop
    sed -i "s/ro.vendor.product.cpu.abilist32=.*/ro.vendor.product.cpu.abilist32=/g" build/portrom/images/vendor/build.prop
    sed -i "s/ro.zygote=.*/ro.zygote=zygote64/g" build/portrom/images/vendor/default.prop
    #cp -rfv devices/32-libs/* build/portrom/images/
fi

if [[ -f devices/${base_product_device}/config ]];then
   source devices/${base_product_device}/config
fi
#rm -rf build/portrom/images/my_manifest
#cp -rf build/baserom/images/my_manifest build/portrom/images/
#cp -rf build/baserom/images/config/my_manifest_* build/portrom/images/config/
sed -i "s/ro.build.display.id=.*/ro.build.display.id=${target_display_id}/g" build/portrom/images/my_manifest/build.prop
sed -i "s/ro.product.first_api_level=.*/ro.product.first_api_level=${base_product_first_api_level}/g" build/portrom/images/my_manifest/build.prop


if  ! grep -q  "ro.build.display.id.show" build/portrom/images/my_manifest/build.prop ;then
    echo "ro.build.display.id.show=$target_display_id_show" >> build/portrom/images/my_manifest/build.prop
else
    sed -i "s/ro.build.display.id.show=.*/ro.build.display.id.show=${target_display_id_show}/g" build/portrom/images/my_manifest/build.prop
fi
sed -i '/ro.build.version.release=/d' build/portrom/images/my_manifest/build.prop
sed -i "s/ro.vendor.oplus.market.name=.*/ro.vendor.oplus.market.name=${base_market_name}/g" build/portrom/images/my_manifest/build.prop
sed -i "s/ro.vendor.oplus.market.enname=.*/ro.vendor.oplus.market.enname=${base_market_enname}/g" build/portrom/images/my_manifest/build.prop

sed -i "s/ro.product.ab_ota_partitions=.*/ro.product.ab_ota_partitions=${base_ab_partitions}/g" build/portrom/images/my_manifest/build.prop
    

sed -i '/ro.oplus.watermark.betaversiononly.enable=/d' build/portrom/images/my_manifest/build.prop

if [[ $base_android_version -le 14 ]];then
    BASE_PROP="build/baserom/images/my_manifest/build.prop"
    PORT_PROP="build/portrom/images/my_manifest/build.prop"

    KEYS="\.name= \.model= \.manufacturer= \.device= \.brand= \.my_product.type="

    for k in $KEYS; do
        grep "$k" "$BASE_PROP" | while IFS='=' read -r key value; do
            if [[ "$key" == "ro.product.vendor.brand" ]]; then
                # 特殊处理：强制写 OPPO
                sed -i "s|^$key=.*|$key=OPPO|" "$PORT_PROP" 
            elif grep -q "^$key=" "$PORT_PROP"; then
                sed -i "s|^$key=.*|$key=$value|" "$PORT_PROP"
            fi
        done
    done
fi
# OOS 16 mixed port
if [[ -n $vendor_cpu_abilist32 ]] ;then
    sed -i "/ro.zygote=zygote64/d" build/portrom/images/my_manifest/build.prop
fi
#其他机型可能没有default.prop
for prop_file in $(find build/portrom/images/vendor/ -name "*.prop"); do
    vndk_version=$(< "$prop_file" grep "ro.vndk.version" | awk "NR==1" | cut -d '=' -f 2)
    if [ -n "$vndk_version" ]; then
        yellow "ro.vndk.version为$vndk_version" "ro.vndk.version found in $prop_file: $vndk_version"
        break  
    fi
done
base_vndk=$(find build/baserom/images/system_ext/apex -type f -name "com.android.vndk.v${vndk_version}.apex")
port_vndk=$(find build/portrom/images/system_ext/apex -type f -name "com.android.vndk.v${vndk_version}.apex")

if [[ ! -f "${port_vndk}" && -f "${base_vndk}" ]]; then
    yellow "apex不存在，从原包复制" "target apex is missing, copying from baserom"
    cp -rf "${base_vndk}" "build/portrom/images/system_ext/apex/"
fi
run_prop_tool batch-dir --dir build/portrom/images --name build.prop \
    --set-existing "ro.build.version.security_patch=${portrom_version_security_patch}"
if [[ $? -eq 127 ]]; then
    for prop in $(find build/portrom/images -name "build.prop");do
        sed -i "s/ro.build.version.security_patch=.*/ro.build.version.security_patch=${portrom_version_security_patch}/g" "$prop"
    done
fi


# Optional identity/PIF assets are installed before framework/APK surgery so
# their init contract, property policy, and shared-library placement are part
# of the extracted tree that later gets repacked. Missing release assets are a
# supported no-op; proprietary payloads are never copied into this checkout.
install_oplus_identity_pif_assets || exit 1
install_property_compat_policy || exit 1
ensure_android_ext_shared_library || exit 1

old_face_unlock_app=$(find build/baserom/images/my_product -type f -name "OPFaceUnlock.apk" -print -quit)
PORT_FRAMEWORK_RES="$(find build/portrom/images/ -type f -name "framework-res.apk" -print -quit)"
export PORT_FRAMEWORK_RES

if [[ "${port_android_version}" == 17 ]]; then
    rm -rf -- build/portrom/images/vendor/app/soterservice
fi

if { [[ ${base_device_family} == "OPSM8250" ]] || [[ ${base_device_family} == "OPSM8350" ]]; } \
   && [[ "${PORT_ENABLE_FACE_UNLOCK_FIX:-false}" == "true" ]]; then
    # The replacement bundle removes vendor HAL/overlay entries and is kept
    # opt-in until the exact base/port camera pair has been validated.
    blue "修复ColorOS15/OxygenOS15 人脸识解锁问题" "COS15/OOS15: Fix Face Unlock for SM8250/8350"
    if ensure_resource_available "devices/common/face_unlock_fix_common.zip"; then
        rm -rf build/portrom/images/vendor/overlay/*
        unzip -qo devices/common/face_unlock_fix_common.zip -d "${work_dir}/build/portrom/images/"
    fi
    if ensure_resource_available "${work_dir}/devices/${base_product_device}/face_unlock_fix.zip" && [[ -f "${old_face_unlock_app}" ]]; then
        unzip -qo "${work_dir}/devices/${base_product_device}/face_unlock_fix.zip" -d "${work_dir}/build/portrom/images/"
        rm -rf build/portrom/images/odm/lib/vendor.oneplus.faceunlock.hal@1.0.so \
            build/portrom/images/odm/bin/hw/vendor.oneplus.faceunlock.hal@1.0-service \
            build/portrom/images/odm/lib/vendor.oneplus.faceunlock.hal-V1-ndk_platform.so \
            build/portrom/images/odm/etc/vintf/manifest/manifest_opfaceunlock.xml \
            build/portrom/images/odm/etc/init/vendor.oneplus.faceunlock.hal@1.0-service.rc \
            build/portrom/images/odm/lib64/vendor.oneplus.faceunlock.hal@1.0.so \
            build/portrom/images/odm/lib64/vendor.oneplus.faceunlock.hal-V1-ndk_platform.so
    fi
fi

if [[ ${base_android_version} == 13 ]] && [[ ${port_android_version} == 14 ]];then
    if ensure_resource_available "devices/common/a13_base_fix.zip"; then
        unzip -qo devices/common/a13_base_fix.zip -d "${work_dir}/build/portrom/images/"
        rm -rf build/portrom/images/odm/bin/hw/vendor.oplus.hardware.charger@1.0-service \
            build/portrom/images/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.charger@1.0-service.rc \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.felica@1.0-service.rc \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.midas@1.0-service.rc \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.wifi@1.1-service-qcom.rc \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_charger.xml \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_felica.xml \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_midas.xml \
            build/portrom/images/odm/etc/vintf/manifest/oplus_wifi_service_device.xml \
            build/portrom/images/odm/framework/vendor.oplus.hardware.wifi-V1.1-java.jar \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.felica@1.0-impl.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.felica@1.0.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.wifi@1.1.so \
            build/portrom/images/odm/overlay/CarrierConfigOverlay.*.apk
    fi
fi

if [[ ${port_android_version} -ge 15 ]]; then
    if [[ ${base_device_family} == "OPSM8250" ]] && [[ ${base_android_version} != 13 ]];then
        if ensure_resource_available "devices/common/ril_fix_sm8250.zip"; then
            unzip -qo devices/common/ril_fix_sm8250.zip -d "${work_dir}/build/portrom/images/"
        fi
        rm -rf build/portrom/images/odm/lib/libmindroid-app.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.subsys_radio-V1-ndk_platform.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.subsys-V1-ndk_platform.so
    elif [[ ${base_device_family} == "OPSM8350" ]];then
        if ensure_resource_available "devices/common/ril_fix_sm8350.zip"; then
            unzip -qo devices/common/ril_fix_sm8350.zip -d "${work_dir}/build/portrom/images/"
        fi
        rm -rf build/portrom/images/odm/lib/libmindroid-app.so \
            build/portrom/images/odm/lib/libmindroid-framework.so \
            build/portrom/images/odm/lib/vendor.oplus.hardware.subsys_radio-V1-ndk_platform.so \
            build/portrom/images/odm/lib/vendor.oplus.hardware.subsys-V1-ndk_platform.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.subsys_radio-V1-ndk_platform.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.subsys-V1-ndk_platform.so
    fi

    if [[ ${base_android_version} == 14 ]]; then
        charger_v3=$(find build/portrom/images/odm/bin/hw/ -type f -name "vendor.oplus.hardware.charger-V3-service" -print -quit)
        if [[ -f "${charger_v3}" ]];then
            if ensure_resource_available "devices/common/charger-v6-update.zip"; then
                unzip -qo devices/common/charger-v6-update.zip -d "${work_dir}/build/portrom/images/"
            fi
            rm -rf build/portrom/images/odm/bin/hw/vendor.oplus.hardware.charger-V3-service \
                build/portrom/images/odm/etc/init/vendor.oplus.hardware.charger-V3-service.rc \
                build/portrom/images/odm/lib/vendor.oplus.hardware.charger-V3-ndk_platform.so \
                build/portrom/images/odm/lib64/vendor.oplus.hardware.charger-V3-ndk_platform.so
        fi
    elif [[ ${base_android_version} == 13 ]];then
        #Ril Fix
        if ensure_resource_available "devices/common/ril_fix_a13_to_a15.zip"; then
            unzip -qo devices/common/ril_fix_a13_to_a15.zip -d "${work_dir}/build/portrom/images/"
        fi
        #Ril Fix for OxygenOS firmware (IN2013/IN2023)
        if ! grep -q "persist.vendor.radio.virtualcomm" build/portrom/images/odm/build.prop;then
            echo "persist.vendor.radio.virtualcomm=1" >> build/portrom/images/odm/build.prop
        fi
        rm -rf build/portrom/images/odm/bin/hw/vendor.oplus.hardware.charger@1.0-service \
            build/portrom/images/odm/bin/hw/vendor.oplus.hardware.wifi@1.1-service \
            build/portrom/images/odm/etc/init/vendor.oneplus.faceunlock.hal@1.0-service.rc \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.charger@1.0-service.rc \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.felica@1.0-service.rc \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.midas@1.0-service.rc \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.wifi@1.1-service-qcom.rc \
            build/portrom/images/odm/etc/vintf/manifest/manifest_opfaceunlock.xml \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_charger.xml \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_cryptoeng_hidl.xml \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_felica.xml \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_midas.xml \
            build/portrom/images/odm/etc/vintf/manifest/oplus_wifi_service_device.xml \
            build/portrom/images/odm/framework/vendor.oplus.hardware.wifi-V1.1-java.jar \
            build/portrom/images/odm/lib/vendor.oneplus.faceunlock.hal@1.0.so \
            build/portrom/images/odm/lib/vendor.oneplus.faceunlock.hal-V1-ndk_platform.so \
            build/portrom/images/odm/lib64/vendor.oneplus.faceunlock.hal@1.0.so \
            build/portrom/images/odm/lib64/vendor.oneplus.faceunlock.hal-V1-ndk_platform.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.felica@1.0-impl.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.felica@1.0.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.subsys_radio-V1-ndk_platform.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.subsys-V1-ndk_platform.so \
            build/portrom/images/odm/lib64/vendor.oplus.hardware.wifi@1.1.so
        #Nfc Fix
        if ensure_resource_available "devices/common/nfc_fix_for_a13.zip"; then
            unzip -qo devices/common/nfc_fix_for_a13.zip -d "${work_dir}/build/portrom/images/"
        fi
        rm -rf build/portrom/images/odm/bin/hw/vendor.oplus.hardware.nfc@1.0-service \
            build/portrom/images/odm/etc/init/vendor.oplus.hardware.nfc@1.0-service.rc \
            build/portrom/images/odm/etc/vintf/manifest/manifest_oplus_nfc.xml \
            build/portrom/images/odm/lib/vendor.oplus.hardware.nfc@1.0.so
        if ensure_resource_available "devices/common/cryptoeng_fix_a13.zip"; then
        # Fix Privacy related features(App lock、App hide)
            unzip -qo devices/common/cryptoeng_fix_a13.zip -d "${work_dir}/build/portrom/images/"
        fi
    fi
fi

# Keep the frame-rate override idempotent.  Re-running a partially completed
# port must not grow build.prop indefinitely.
grep -qF 'ro.surface_flinger.game_default_frame_rate_override=120' \
    build/portrom/images/vendor/default.prop 2>/dev/null || \
    echo 'ro.surface_flinger.game_default_frame_rate_override=120' >> \
        build/portrom/images/vendor/default.prop

if [[ $port_android_version == 16 || $port_android_version == 17 ]] && [[ $base_android_version -lt 15 ]] ;then
    # workaround fix AI Eraser
    if [[ -f build/portrom/images/odm/lib64/libaiboost.so ]]; then
        mkdir -p build/portrom/images/my_product/lib64/
        cp -p build/portrom/images/odm/lib64/libaiboost.so \
            build/portrom/images/my_product/lib64/libaiboost.so
    else
        yellow "未找到 libaiboost.so，跳过 AI Eraser 兼容补位" "libaiboost.so not found; skipping AI Eraser backfill"
    fi
fi

_xeutoolbox_applied=false
if ensure_resource_available "devices/common/xeutoolbox.zip" && [[ $base_android_version -lt 15 ]] && [[ ${portIsColorOSGlobal} != true ]];then
    blue "Integrated Xiami EU xeutoolbox"
    echo "/system_ext/xbin/xeu_toolbox  u:object_r:toolbox_exec:s0" >> build/portrom/images/config/system_ext_file_contexts
    echo "/system_ext/xbin/xeu_toolbox  u:object_r:toolbox_exec:s0" >> build/portrom/images/system_ext/etc/selinux/system_ext_file_contexts
    echo "(allow init toolbox_exec (file ((execute_no_trans))))" >> build/portrom/images/system_ext/etc/selinux/system_ext_sepolicy.cil
    unzip -qo devices/common/xeutoolbox.zip -d build/portrom/images/
    _xeutoolbox_applied=true
fi

# Keep the donor OTA application: no release replacement, cached patched APK,
# decoding or dm-verity patching is applied here.
blue "保留移植包原始 OTA.apk" "Keeping the donor OTA.apk unchanged"

mkdir -p tmp "build/${app_patch_folder}/patched"
_apk_patch_targets=(services framework oplus_services HeyTapSpeechAssist AIUnit SystemUI)
if [[ "${_xeutoolbox_applied}" != true && $base_android_version -lt 15 ]]; then
    _apk_patch_targets+=(OppoGallery2)
fi
if [[ ${base_device_family} == "OPSM8250" ]] || [[ ${base_device_family} == "OPSM8350" ]]; then
    _apk_patch_targets+=(Battery)
fi
if [[ ${regionmark} != "CN" ]] && [[ ${base_product_model} != IN20* ]]; then
    _apk_patch_targets+=(Settings)
fi
if [[ ${base_product_first_api_level:-0} -gt 34 ]]; then
    _apk_patch_targets+=(OplusLauncher)
fi
if [[ ${base_product_first_api_level:-0} -le 35 ]]; then
    _apk_patch_targets+=(Aod)
fi
if [[ ${port_android_version:-0} -ge 16 ]]; then
    _apk_patch_targets+=(Wallpapers)
fi

_patch_jobs="$(port_patch_job_count "$(port_cpu_count)")" || exit 2
blue "并行修补 APK/JAR (${_patch_jobs} 线程)" "Patching APKs/JARs in parallel (${_patch_jobs} job(s))"
port_run_jobs "${_patch_jobs}" "${work_dir}/build/logs/patch-apks" _port::patch_apk_worker "${_apk_patch_targets[@]}" || {
    error "APK/JAR 修补失败" "APK/JAR patching failed"
    exit 1
}
yellow "删除多余的App" "Debloating..." 
# List of apps to be removed

debloat_apps=("HeartRateDetect" "Browser")
#kept_apps=("Clock" "FileManager" "KeKeThemeSpace" "SogouInput" "Weather" "Calendar")
#kept_apps=("BackupAndRestore" "Calculator2" "Calendar" "Clock" "FileManager" "OppoNote2" "OppoWeather2" "UPTsmService" "Music")
kept_apps=("OppoNote2" "OppoWeather2")
#kept_apps=()

if [[ $super_extended == "true" ]] && [[ $pack_method == "stock" ]] && [[ -f build/baserom/images/reserve.img ]]; then
    rm -rf build/baserom/images/reserve.img
elif [[ $super_extended == "false" ]] && [[ $pack_method == "stock" ]] && [[ -f build/baserom/images/reserve.img ]]; then
    #extract_partition "${work_dir}/build/baserom/images/reserve.img" "${work_dir}/build/baserom/images/"
    #if [[ -f ext/del-app-ksu-module/system/product/app/* ]];then
    ##    rm -rf ext/del-app-ksu-module/system/product/app/*
    #fi
    #ext_moudle_app_folder="ext/del-app-ksu-module/system/product/app"
    for delapp in $(find build/portrom/images/ -maxdepth 3 -path "*/del-app/*" -type d);do
        
        app_name=$(basename "$delapp")

        # Check if the app is in kept_apps, skip if true
        keep_app=false
        for kept_app in "${kept_apps[@]}"; do
            [[ "${app_name}" == "${kept_app}" ]] && keep_app=true && break
        done
        if [[ "${keep_app}" == true ]]; then
            echo "Skipping kept app: $app_name"
        continue
        fi
        #mv -fv $delapp ${ext_moudle_app_folder}/
        rm -rf $delapp 
    done 

    for debloat_app in "${debloat_apps[@]}"; do
    # Find the app directory
    app_dir=$(find build/portrom/images/ -type d -name "*$debloat_app*")
    
    # Check if the directory exists before removing
    if [[ -d "$app_dir" ]]; then
        yellow "删除目录: $app_dir" "Removing directory: $app_dir"
        rm -rf "$app_dir"
    fi
    done

    if [[ -d devices/common/via ]]; then
        mkdir -p build/portrom/images/product/app/
        cp -rf devices/common/via build/portrom/images/product/app/
    fi
elif [[ $super_extended == "false" ]] && [[ $base_product_model == "KB2000" ]] && [[ "$is_ab_device" == true ]];then
    for delapp in $(find build/portrom/images/ -maxdepth 3 -path "*/del-app/*" -type d ); do
        app_name=$(basename ${delapp})
        
        keep=false
        for kept_app in "${kept_apps[@]}"; do
            if [[ $app_name == *"$kept_app"* ]]; then
                keep=true
                break
            fi
        done
        
        if [[ $keep == false ]]; then
            debloat_apps+=("$app_name")
        fi

    done
    for debloat_app in "${debloat_apps[@]}"; do
    # Find the app directory
    app_dir=$(find build/portrom/images/ -type d -name "*$debloat_app*")
    
    # Check if the directory exists before removing
    if [[ -d "$app_dir" ]]; then
        yellow "删除目录: $app_dir" "Removing directory: $app_dir"
        rm -rf "$app_dir"
    fi
    done
elif [[ $super_extended == "false" ]] && [[ $base_product_model == "KB200"* ]] && [[ "$is_ab_device" == true ]];then
    debloat_apps=("Facebook" "YTMusic" "GoogleHome" "GoogleOne" "Videos_del" "Drive_del" "ConsumerIRApp" "YouTube" "Gmail2" "Maps" "Wellbeing" "OPForum" "INOnePlusStore" "YTMusic_del" "ConsumerIRApp" "Meet")
    for debloat_app in "${debloat_apps[@]}"; do
    # Find the app directory
    app_dir=$(find build/portrom/images/ -type d -name "*$debloat_app*")
    
    # Check if the directory exists before removing
    if [[ -d "$app_dir" ]]; then
        yellow "删除目录: $app_dir" "Removing directory: $app_dir"
        rm -rf "$app_dir"
    fi
    done
    
    #rm -rfv build/portrom/images/my_stock/del-app/*
elif [[ $super_extended == "false" ]] && [[ $base_product_model == "LE2101" ]];then
      debloat_apps=("Facebook" "YTMusic" "GoogleHome" "GoogleOne" "Videos_del" "Drive_del" "ConsumerIRApp" "YouTube" "Gmail2" "Maps" "Wellbeing" "OPForum" "INOnePlusStore" "YTMusic_del" "ConsumerIRApp" "Meet")
    for debloat_app in "${debloat_apps[@]}"; do
    # Find the app directory
    app_dir=$(find build/portrom/images/ -type d -name "*$debloat_app*")
    
    # Check if the directory exists before removing
    if [[ -d "$app_dir" ]]; then
        yellow "删除目录: $app_dir" "Removing directory: $app_dir"
        rm -rf "$app_dir"
    fi
    done
  #rm -rfv build/portrom/images/my_stock/del-app/*
fi
rm -rf build/portrom/images/product/etc/auto-install*
rm -rf build/portrom/images/system/verity_key
rm -rf build/portrom/images/vendor/verity_key
rm -rf build/portrom/images/product/verity_key
rm -rf build/portrom/images/system/recovery-from-boot.p
rm -rf build/portrom/images/vendor/recovery-from-boot.p
rm -rf build/portrom/images/product/recovery-from-boot.p

# build.prop 修改

sed -i "/ro.oplus.audio.*/d" build/portrom/images/my_product/build.prop

prepare_base_prop
add_prop_from_port

blue "正在修改 build.prop" "Modifying build.prop"


#change the locale to English
export LC_ALL=en_US.UTF-8
buildDate=$(date -u +"%a %b %d %H:%M:%S UTC %Y")
buildUtc=$(date +%s)
_prop_batch_dir_script() {
    printf 'set-existing persist.sys.timezone=Asia/Shanghai\n'
    [[ -n "${port_device_code}" && -n "${base_device_code}" && "${port_device_code}" != "${base_device_code}" ]] && \
        printf 'replace %s=%s\n' "${port_device_code}" "${base_device_code}"
    [[ -n "${port_product_model}" && -n "${base_product_model}" && "${port_product_model}" != "${base_product_model}" ]] && \
        printf 'replace %s=%s\n' "${port_product_model}" "${base_product_model}"
    [[ -n "${port_product_name}" && -n "${base_product_name}" && "${port_product_name}" != "${base_product_name}" ]] && \
        printf 'replace %s=%s\n' "${port_product_name}" "${base_product_name}"
    [[ -n "${port_my_product_type}" && -n "${base_my_product_type}" && "${port_my_product_type}" != "${base_my_product_type}" ]] && \
        printf 'replace %s=%s\n' "${port_my_product_type}" "${base_my_product_type}"
    [[ -n "${port_product_device}" && -n "${base_product_device}" && "${port_product_device}" != "${base_product_device}" ]] && \
        printf 'replace %s=%s\n' "${port_product_device}" "${base_product_device}"
    printf 'set-existing ro.build.user=%s\n' "${build_user}"
    printf 'set-existing ro.build.display.id=%s\n' "${target_display_id}"
    printf 'set-existing ro.oplus.radio.global_regionlock.enabled=false\n'
    printf 'set-existing persist.sys.radio.global_regionlock.allcheck=false\n'
    printf 'set-existing ro.oplus.radio.checkservice=false\n'
    if [[ "${portIsColorOSGlobal}" == true ]]; then
        printf 'regex-replace =OnePlus[[:space:]]*$==OPPO\n'
    fi
}
_prop_batch_dir_script | run_prop_tool batch-dir --dir build/portrom/images --name build.prop --stdin
_prop_batch_dir_rc=$?
if [[ ${_prop_batch_dir_rc} -eq 127 ]]; then
    for i in $(find build/portrom/images -type f -name "build.prop");do
        blue "正在处理 ${i}" "modifying ${i}"
        sed -i "s/persist.sys.timezone=.*/persist.sys.timezone=Asia\/Shanghai/g" "${i}"
        #全局替换device_code
        sed -i "s/$port_device_code/$base_device_code/g" "${i}"
        sed -i "s/$port_product_model/$base_product_model/g" "${i}"
        sed -i "s/$port_product_name/$base_product_name/g" "${i}"
        sed -i "s/$port_my_product_type/$base_my_product_type/g" "${i}"
        sed -i "s/$port_product_device/$base_product_device/g" "${i}"
        # 添加build user信息
        sed -i "s/ro.build.user=.*/ro.build.user=${build_user}/g" "${i}"
        sed -i "s/ro.build.display.id=.*/ro.build.display.id=${target_display_id}/g" "${i}"
        sed -i "s/ro.oplus.radio.global_regionlock.enabled=.*/ro.oplus.radio.global_regionlock.enabled=false/g" "${i}"
        sed -i "s/persist.sys.radio.global_regionlock.allcheck=.*/persist.sys.radio.global_regionlock.allcheck=false/g" "${i}"
        sed -i "s/ro.oplus.radio.checkservice=.*/ro.oplus.radio.checkservice=false/g" "${i}"
        if [[ $portIsColorOSGlobal == true ]];then
            sed -i 's/=OnePlus[[:space:]]*$/=OPPO/' "${i}"
        fi
    done
elif [[ ${_prop_batch_dir_rc} -ne 0 ]]; then
    exit "${_prop_batch_dir_rc}"
fi

sed -i "s/ro.vendor.oplus.market.name=.*/ro.vendor.oplus.market.name=${base_market_name}/g" build/portrom/images/my_product/etc/bruce/build.prop
sed -i "s/ro.vendor.oplus.market.enname=.*/ro.vendor.oplus.market.enname=${base_market_enname}/g" build/portrom/images/my_product/etc/bruce/build.prop

remove_prop_v2 "persist.oplus.software.audio.right_volume_key"
remove_prop_v2 "persist.oplus.software.alertslider.location"


sed -i -e '$a\'$'\n''persist.adb.notify=0' build/portrom/images/system/system/build.prop
sed -i -e '$a\'$'\n''persist.sys.usb.config=mtp,adb' build/portrom/images/system/system/build.prop
sed -i -e '$a\'$'\n''persist.sys.disable_rescue=true' build/portrom/images/system/system/build.prop

base_rom_density=$(grep "ro.sf.lcd_density" --include="*.prop" -r build/baserom/images/my_product | head -n 1 | cut -d "=" -f2)
[ -z "${base_rom_density}" ] && base_rom_density=480

# if grep -q "ro.sf.lcd_density" build/portrom/images/my_product/build.prop ;then
#         sed -i "s/ro.sf.lcd_density=.*/ro.sf.lcd_density=${base_rom_density}/g" build/portrom/images/my_product/build.prop
# else
#         echo "ro.sf.lcd_density=${base_rom_density}" >> build/portrom/images/my_product/build.prop
# fi

# brand require lowercase
base_vendor_brand_lower="$(_port::lower "${base_vendor_brand}")"
port_vendor_brand_lower="$(_port::lower "${port_vendor_brand}")"
if [[ ${base_vendor_brand_lower} != ${port_vendor_brand_lower} ]] && [[ $portIsColorOSGlobal == false ]] && [[ $port_android_version -lt 16 ]];then
    # Global ColorOS needs to be Oppo brand or stuck on 
    sed -i "s/ro.oplus.image.system_ext.brand=.*/ro.oplus.image.system_ext.brand=${base_vendor_brand_lower}/g" build/portrom/images/system_ext/etc/build.prop
fi

# fix bootloop
if [[ -f build/baserom/images/my_product/etc/extension/sys_game_manager_config.json ]];then
    cp -rf build/baserom/images/my_product/etc/extension/sys_game_manager_config.json build/portrom/images/my_product/etc/extension/
else
    rm -rf build/portrom/images/my_product/etc/extension/sys_game_manager_config.json
fi

if [[ ! -f build/baserom/images/my_product/etc/extension/sys_graphic_enhancement_config.json ]];then
    rm -rf build/portrom/images/my_product/etc/extension/sys_graphic_enhancement_config.json
else
    cp -rf build/baserom/images/my_product/etc/extension/sys_graphic_enhancement_config.json build/portrom/images/my_product/etc/extension/
fi

if [[ $(cat build/baserom/images/my_product/build.prop | grep "ro.oplus.audio.effect.type" | cut -d "=" -f 2) == "dolby" ]] ;then
blue "修复杜比音效+多应用音量调节 SM8250/SM8350" "Fix Dolby + App Specific volume adjustment for SM8250/SM8350"
     #cp $source_dolby_lib build/portrom/images/system_ext/lib64/
     cp build/baserom/images/my_product/etc/permissions/oplus.product.features_dolby_stereo.xml build/portrom/images/my_product/etc/permissions/oplus.product.features_dolby_stereo.xml
     if ensure_resource_available "devices/common/dolby_fix.zip"; then
         unzip -qo devices/common/dolby_fix.zip -d build/portrom/images/ 
     fi
fi


# Fix wechat/whatsapp volume isue
cp -rf build/baserom/images/my_product/etc/audio*.xml build/portrom/images/my_product/etc/
cp -rf build/baserom/images/my_product/etc/default_volume_tables.xml build/portrom/images/my_product/etc/
if [[ -d build/baserom/images/my_product/etc/breenospeech2 ]];then
    cp -rf build/baserom/images/my_product/etc/breenospeech2/* build/portrom/images/my_product/etc/breenospeech2/
fi
if [[ -d build/baserom/images/my_product/etc/fusionlight_profile ]]; then
    mkdir -p build/portrom/images/my_product/etc/fusionlight_profile/
    rm -rf build/portrom/images/my_product/etc/fusionlight_profile/*
    cp -rf build/baserom/images/my_product/etc/fusionlight_profile/* build/portrom/images/my_product/etc/fusionlight_profile/
fi
# Fix game audio issue on 15.0.2 (13t)

sed -i "/persist.vendor.display.pxlw.iris_feature=.*/d" build/portrom/images/my_product/etc/bruce/build.prop

if [[ $portIsRealmeUI == true ]]; then
    case $port_android_version in
        16) rui_version=7.0;;
        15) rui_version=6.0;;
        14) rui_version=5.0;;
        *) rui_version="";;
    esac
    if [[ -n "${rui_version}" ]] && ! grep -qF "ro.build.version.realmeui=${rui_version}" \
        build/portrom/images/my_product/etc/bruce/build.prop 2>/dev/null; then
        echo "ro.build.version.realmeui=${rui_version}" >> build/portrom/images/my_product/etc/bruce/build.prop
    fi

fi

propfile="build/portrom/images/my_product/etc/bruce/build.prop"

# PropsHook now stores per-app rules in Settings.Global.  Predeclaring the old
# persist.oplus.* entries consumes the small Android property area and can
# prevent unrelated system_server properties from being created.  Remove only
# rules emitted by older builds; explicit user-managed properties are left
# untouched.
if [[ -f "${propfile}" ]]; then
    sed -i -E \
        -e '/^persist\.sys\.prophook\.com\.oplus\.(ai\.magicstudio|aiunit)=/d' \
        -e '/^persist\.oplus\.prophook\.com\.oplus\.(ai\.magicstudio|aiunit)=/d' \
        -e '/^persist\.sys\.prophook\.com\.coloros\.smartsidebar=/d' \
        -e '/^persist\.oplus\.prophook\.com\.coloros\.smartsidebar=/d' \
        "${propfile}"
fi

if [[ "${stock_is_tablet}" == false && "${port_is_tablet}" == true ]]; then
    blue "检测到跨平板模式移植，删除平板属性" "Cross-tablet mode detected, removing tablet properties"
    run_prop_tool batch \
        --file build/portrom/images/my_product/build.prop \
        --bruce-file build/portrom/images/my_product/etc/bruce/build.prop \
        --base build/baserom/images/my_product/build.prop \
        --stdin <<'EOF'
comment-force ro.oplus.vpp.device.type
comment-force ro.build.characteristics
comment-force ro.panel.pad
comment ro.oplus.vrr.pencil.support
comment ro.audio.tablet.mic_type
comment persist.settings.large_screen_opt.enabled
comment ro.oplus.tablet
comment ro.vendor.radio.noril
comment ro.radio.noril
EOF
    if [[ $? -eq 127 ]]; then
        remove_prop_v2 "ro.oplus.vpp.device.type" force
        remove_prop_v2 "ro.build.characteristics" force
        remove_prop_v2 "ro.panel.pad" force
        remove_prop_v2 "ro.oplus.vrr.pencil.support"
        remove_prop_v2 "ro.audio.tablet.mic_type"
        remove_prop_v2 "persist.settings.large_screen_opt.enabled"
        remove_prop_v2 "ro.oplus.tablet"
        remove_prop_v2 "ro.vendor.radio.noril"
        remove_prop_v2 "ro.radio.noril"
    fi
    run_xml_tool add-features --port-dir build/portrom/images/my_product/etc --stdin <<'EOF'
app_feature	com.android.launcher.TASKBAR_ENABLE
app_feature	com.oplus.aimemory.mind_map_enable
permission_feature	oplus.software.ai_key_multi_enable
EOF
    if [[ $? -eq 127 ]]; then
        add_feature_v2 app_feature "com.android.launcher.TASKBAR_ENABLE"
        add_feature_v2 app_feature "com.oplus.aimemory.mind_map_enable"
        add_feature_v2 permission_feature "oplus.software.ai_key_multi_enable"
    fi
    remove_feature "oplus.hardware.type.tablet"

    # Phone-compatible framework APKs are safer than carrying tablet overlays
    # across an otherwise phone base.
    for apk_name in Aod.apk PhoneManager.apk OplusBootReg.apk; do
        baserom_apk=$(find build/baserom/images -type f -name "${apk_name}" -print -quit)
        if [[ -n "${baserom_apk}" ]]; then
            baserom_apk_dir=$(dirname "${baserom_apk}")
            portrom_apk_dir="${baserom_apk_dir/build\/baserom\/images/build\/portrom\/images}"
            mkdir -p "${portrom_apk_dir}"
            cp -p -- "${baserom_apk}" "${portrom_apk_dir}/" || exit 1
        fi
    done
    for apk_name in StudyCenter.apk PadConnect.apk PCEngine.apk HotGamesFolder.apk WpsLauncher.apk; do
        portrom_apk=$(find build/portrom/images -type f -name "${apk_name}" -print -quit)
        [[ -n "${portrom_apk}" ]] || continue
        apk_dir=$(dirname "${portrom_apk}")
        case "$(basename "${apk_dir}")" in
            app|priv-app|del-app) rm -f -- "${portrom_apk}" || exit 1 ;;
            *) rm -rf -- "${apk_dir}" || exit 1 ;;
        esac
    done
fi
_prop_batch_v2_script() {
    cat <<'EOF'
comment ro.oplus.resolution
comment ro.oplus.display.wm_size_resolution_switch.support
comment ro.density.screenzoom
comment ro.oplus.density.qhd_default
comment ro.oplus.density.fhd_default
comment ro.oplus.key.actionbutton
comment ro.oplus.audio.support.foldingmode
comment ro.config.fold_disp
comment persist.oplus.display.fold.support
comment ro.oplus.haptic
comment ro.vendor.mtk
comment ro.oplus.mtk
comment persist.sys.oplus.wlan.atpc.qcom_use_iw
comment ro.product.oplus.cpuinfo
comment ro.product.oplus.device
EOF
    if [[ $base_android_version -lt 15 ]] && [[ $port_android_version -gt 15 ]]; then
        printf 'comment ro.lcd.display.screen\ncomment ro.display.brightness\ncomment ro.oplus.lcd.display\n'
    fi
    printf 'ro.oplus.game.camera.support_1_0=true\nro.oplus.audio.quiet_start=true\n'
    printf 'debug.sf.oplus_display_trace.enable=0\n'
    printf 'debug.oplus.systrace_enhance=false\n'
    printf 'ro.audio.voiplog.on=false\n'
    printf 'persist.device_config.runtime_native_boot.iorap_perfetto_enable=false\n'
    printf 'ro.oplus.osense.uaf_vip_binder_enable=true\n'
    if [[ "$portIsOOS" == "true" ]]; then
        printf 'comment-force ro.oplus.camera.quickshare.support\n'
    fi
    if [[ $port_android_version -lt 16 ]]; then
        if [[ $base_device_family == "OPSM8250" ]] || [[ $base_device_family == "OPSM8350" ]]; then
            printf 'persist.sys.oplus.anim_level=2\n'
        else
            printf 'persist.sys.oplus.anim_level=1\n'
        fi
    fi
    printf 'ro.sf.lcd_density=%s\n' "${base_rom_density}"
}
_prop_batch_v2_script | run_prop_tool batch \
    --file build/portrom/images/my_product/build.prop \
    --bruce-file build/portrom/images/my_product/etc/bruce/build.prop \
    --base build/baserom/images/my_product/build.prop \
    --stdin
_prop_batch_v2_rc=$?
if [[ ${_prop_batch_v2_rc} -eq 127 ]]; then
    remove_prop_v2 "ro.oplus.resolution"
    remove_prop_v2 "ro.oplus.display.wm_size_resolution_switch.support"
    remove_prop_v2 "ro.density.screenzoom"
    remove_prop_v2 "ro.oplus.resolution"
    remove_prop_v2 "ro.oplus.density.qhd_default"
    remove_prop_v2 "ro.oplus.density.fhd_default"
    remove_prop_v2 "ro.oplus.key.actionbutton"
    remove_prop_v2 "ro.oplus.audio.support.foldingmode"
    remove_prop_v2 "ro.config.fold_disp"
    remove_prop_v2 "persist.oplus.display.fold.support"
    remove_prop_v2 "ro.oplus.haptic"

    remove_prop_v2 "ro.vendor.mtk"
    remove_prop_v2 "ro.oplus.mtk"
    # OnePlus 8T: Fix OpSynergy crash
    remove_prop_v2 "persist.sys.oplus.wlan.atpc.qcom_use_iw"

    remove_prop_v2 "ro.product.oplus.cpuinfo"
    remove_prop_v2 "ro.product.oplus.device"
    if [[ $base_android_version -lt 15 ]] && [[ $port_android_version -gt 15 ]];then
        remove_prop_v2 "ro.lcd.display.screen"
        remove_prop_v2 "ro.display.brightness"
        remove_prop_v2 "ro.oplus.lcd.display"
        #remove_prop_v2 "ro.display.brightness.curve.name" force
    fi

    add_prop_v2 "ro.oplus.game.camera.support_1_0" "true"
    add_prop_v2 "ro.oplus.audio.quiet_start" "true"
    add_prop_v2 "debug.sf.oplus_display_trace.enable" "0"
    add_prop_v2 "debug.oplus.systrace_enhance" "false"
    add_prop_v2 "ro.audio.voiplog.on" "false"
    add_prop_v2 "persist.device_config.runtime_native_boot.iorap_perfetto_enable" "false"
    add_prop_v2 "ro.oplus.osense.uaf_vip_binder_enable" "true"
    if [[ $portIsOOS == "true" ]];then
        remove_prop_v2 "ro.oplus.camera.quickshare.support" force
    fi

    if [[ $port_android_version -lt 16 ]];then

        if [[ $base_device_family == "OPSM8250" ]] || [[ $base_device_family == "OPSM8350" ]];then
            add_prop_v2 "persist.sys.oplus.anim_level" "2"
        else
            add_prop_v2 "persist.sys.oplus.anim_level" "1"
        fi
    fi
    add_prop_v2 "ro.sf.lcd_density" "${base_rom_density}"
elif [[ ${_prop_batch_v2_rc} -ne 0 ]]; then
    exit "${_prop_batch_v2_rc}"
fi

cp -rf build/baserom/images/my_product/app/com.oplus.vulkanLayer build/portrom/images/my_product/app/
cp -rf build/baserom/images/my_product/app/com.oplus.gpudrivers.* build/portrom/images/my_product/app/

mkdir -p tmp/etc/permissions tmp/etc/extension
cp -f build/portrom/images/my_product/etc/permissions/*.xml tmp/etc/permissions/
cp -f build/portrom/images/my_product/etc/extension/*.xml tmp/etc/extension/
cp -rf build/baserom/images/my_product/etc/permissions/*.xml build/portrom/images/my_product/etc/permissions/
find tmp/etc/permissions/ -type f \( -name "multimedia*.xml" -o -name "*permissions*.xml" -o -name "*google*.xml" -o -name "*configs*.xml" -o -name "*gsm*.xml" -o -name "feature_activity_preload.xml" -o -name "*gemini*.xml" -o -name "*gms*.xml" -o -name "*camera*.xml" \) -exec cp -f {} build/portrom/images/my_product/etc/permissions/ \;


if [[ $regionmark != "CN" ]];then
    run_xml_tool delete-elements \
        --file build/portrom/images/my_stock/etc/config/app_v2.xml \
        --attr pkg \
        --value com.android.contacts \
        --value com.android.incallui \
        --value com.android.mms \
        --value com.oplus.blacklistapp \
        --value com.oplus.phonenoareainquire \
        --value com.ted.number
    if [[ $? -eq 127 ]]; then
        for i in com.android.contacts com.android.incallui com.android.mms com.oplus.blacklistapp com.oplus.phonenoareainquire com.ted.number; do
            sed -i "/$i/d" build/portrom/images/my_stock/etc/config/app_v2.xml
        done
    fi
fi

cp -rf build/baserom/images/my_product/etc/extension/*.xml build/portrom/images/my_product/etc/extension/
cp -rf  build/baserom/images/my_product/etc/refresh_rate_config.xml build/portrom/images/my_product/etc/refresh_rate_config.xml

#cp -rf build/baserom/images/my_product/etc/extension/*.xml build/portrom/images/my_product/etc/extension/

cp -rf  build/baserom/images/my_product/etc/sys_resolution_switch_config.xml build/portrom/images/my_product/etc/sys_resolution_switch_config.xml

cp -rf build/baserom/images/my_product/etc/permissions/com.oplus.sensor_config.xml build/portrom/images/my_product/etc/permissions/
# add_feature "com.android.systemui.support_media_show" build/portrom/images/my_product/etc/extension/com.oplus.app-features.xml

# Features Extension

oplus_features=(
    "oplus.software.directservice.finger_flashnotes_enable^小布记忆" 
    "oplus.software.support_quick_launchapp"  
    "oplus.software.support_blockable_animation" 
    "oplus.software.support.zoom.multi_mode" 
    #"oplus.software.radio.networkless_support^无网畅聊" 
    #"oplus.software.display.ai_eyeprotect_v1_support^AI护眼"
    "oplus.software.display.reduce_white_point^降低白点值"
    "oplus.software.audio.media_control"
    "oplus.software.support.zoom.open_wechat_mimi_program"
    "oplus.software.support.zoom.center_exit"
    "oplus.software.support.zoom.game_enter" 
    "oplus.software.coolex.support"
    "oplus.software.display.game.dapr_enable"
    "oplus.software.display.eyeprotect_game_support"
    "oplus.software.multi_app.volume.adjust.support^多音量调节（A13机型没有）" 
    "oplus.software.systemui.navbar_pick_color^15.0.2.201新增"
    "oplus.software.string_gc_support"
    "oplus.software.display.rgb_ball_support^色温调节球"
    "oplus.software.camera_volume_quick_launch" #GT5Pro
    "oplus.software.display.intelligent_color_temperature_support"
    "oplus.software.display.oha_support"
    "oplus.software.display.smart_color_temperature_rhythm_health_support"
    "oplus.software.display.mura_enhance_brightness_support"
    "oplus.software.audio.assistant_volume_support"
    "oplus.software.audio.volume_default_adjust"
    "oplus.software.notification_alert_support_fifo"
    "oplus.software.game_scroff_act_preload"
    "oplus.software.display.game_dark_eyeprotect_support^游戏助手夜晚护眼"
    "oplus.software.systemui.navbar_pick_color^小横条拾取颜色优化"
    "oplus.software.smart_sidebar_video_assistant^侧边栏视频助手"
    "oplus.video.audio.volume.enhancement^视频音量增强" 
    "oplus.software.display.lux_small_debounce_expand_support"
    "oplus.hardware.display.no_bright_eyes_low_freq_strobe^低亮度屏闪"
    "oplus.software.audio.super_volume_4x^400%超级音量"
    "oplus.software.radio.networkless_sms_support"
    "com.oplus.location.car_phone_connection"
   "oplus.software.display.enhance_brightness_with_uidimming^LocalHDR"
    "oplus.software.adaptive_smooth_animation^山海通信网络引擎"
    "oplus.software.radio.ai_link_boost"
    "oplus.software.radio.ai_link_boost_notification"
    "oplus.software.radio.ai_link_boost_railway_notification"
    "oplus.software.systemui.pin_task^钉到流体云"
    "oplus.software.radio.hfp_comm_shared_support^iPhone互联"
    "oplus.hardware.display.motion_sickness^晕动舒缓提示"
    "oplus.software.radio.nwpower_amc_special_sim"
    "oplus.software.radio.mdlog_buffer_qdss_enable"
    "oplus.software.radio.hfp_comm_shared_support"
)

app_features=(
    "os.personalization.flip.agile_window.enable"
    "os.personalization.wallpaper.live.ripple.enable"
    "com.oplus.infocollection.screen.recognition"
    "os.graphic.gallery.os15_secrecy^^args=\"boolean:true\""
    "com.coloros.colordirectservice.cm_enable^^args=\"boolean:true\""
    "com.oplus.exserviceui.feature_zoom_drag"
    "feature.hottouch.anim.support"
    "os.charge.settings.longchargeprotection.ai"
    "os.charge.settings.smartchargeswitch.open"
    "com.oplus.eyeprotect.ai_intelligent_eye_protect_support"
    "com.android.settings.network_access_permission"
    "os.charge.settings.batterysettings.batteryhealth^电池健康度"
    "com.oplus.mediaturbo.service"
    "com.oplus.mediaturbo.game_live^直播助手"
    "oplus.aod.wakebyclick.support^点击屏幕唤醒息屏"
    "com.oplus.screenrecorder.area_record^区域截图^args=\"boolean:true\""
    "com.oplus.systemui.panoramic_aod.enable^^args=\"boolean:true\""
    "com.android.systemui.qs_deform_enable^^args=\"boolean:true\""
    "com.oplus.mediaturbo.tencent_meeting^腾讯会议^args=\"boolean:true\""
    "com.oplus.note.aigc.ai_rewrtie.support^AI帮写"
    #"feature.super_settings_smart_touch_v2.support^隔膜触控V2"
    "com.oplus.games.show_bypass_charging_when_gameapps^旁路供电^args=\"boolean:true\""
    "com.oplus.wallpapers.livephoto_wallpaper^^args=\"boolean:true\""
    "com.oplus.battery.autostart_limit_num^^args=\"String:8|10-16|15-24|20\""
    "com.android.launcher.recent_lock_limit_num^^args=\"String:8|10-16|15-24|20\""
    "com.oplus.battery.whitelist_vowifi^^args=\"boolean:true\""
    "com.oplus.battery.support.smart_refresh" # GT5Pro
    "com.oplus.battery.life.mode.notificate^^args=\"int:1\"" # 13T indicate if the device is support life mode 1.0：1 2.0：2
    "feature.support.game.AI_PLAY" #GT5Pro
    "feature.support.game.AI_PLAY_version3" # GT5Pro

    "feature.super_app_alive.support_min_ram^^args=\"int:12\""
    "feature.super_app_alive.support_flag^^args=\"int:15\""
    "feature.super_alive_game.support^^args=\"int:1\""
    "feature.super_settings_smart_touch.support^隔膜触控V1"
    "com.android.launcher.folder_content_recommend_disable"
    "com.android.launcher.rm_disable_folder_footer_ad"
    "feature.support.game.ASSIST_KEY"
    "oplus.software.vibration_custom"
    "com.oplus.smartmediacontroller.lss_assistant_enable^侧边栏声音分轨助手"
    # "com.android.incallui.share_screen_and_touch_cmd_support^电话触摸分享与屏幕共享" 会导致OOS 拨打电话崩溃
    "com.oplus.phonemanager.ai_voice_detect^合成语音^args=\"int:1\""
    "com.oplus.directservice.aitoolbox_enable^^args=\"boolean:true\""
    "com.coloros.support_gt_boost^^args=\"boolean:true\""
    "com.oplus.aicall.call_translate"
    "com.oplus.gesture.camera_space_gesture_support^隔空手势" #需要替换RM设备的OplusGesture App才能开启
    "com.oplus.gesture.intelligent_perception"
    "com.oplus.dmp.aiask_enable^AI搜索^args=\"int:1\""
    "os.graphic.gallery.photoeditor.aibesttake^最佳摄影功能^args=\"int:1\""
    "com.oplus.tips.os_recommend_page_index^新功能推荐^args=\"String:indexOS15_0_2_new\""
    "com.oplus.mediaturbo.transcoding^^args=\"boolean:true\""
    "com.android.launcher.app_advice_autoadd^^args=\"boolean:true\""
    "com.android.launcher.INDICATOR_BREENO_ENTRY_ENABLE^系统桌面小布提示^args=\"boolean:true\""
    #ColorOS 16 new added
    "com.oplus.systemui.panoramic_aod.enable^AOD^args=\"boolean:true\""
    "oplus.software.disable_aod_all_day_mode^^args=\"boolean:false\""
    "com.oplus.systemui.panoramic_aod_all_day_default_open.enable^^args=\"boolean:true\""
    "com.oplus.systemui.panoramic_aod_all_day.enable^^args=\"boolean:true\""
    "oplus_keyguard_panoramic_aod_all_day_support^^args=\"boolean:true\""
    "com.oplus.securityguard.sample.feature_enable^安全管家相关^args=\"boolean:true\""
    "com.oplus.aiwriter.input_entrance_enabled^^args=\"boolean:true\""
    "com.oplus.persona.card_datamining_support^^args=\"boolean:true\""
    "os.graphic.gallery.collage.livephoto^^args=\"boolean:true\""
    "com.android.systemui.qs_deform_enable^^args=\"boolean:true\""
    "com.oplus.wallpapers.ai_camera_movement^^args=\"boolean:true\""
    "com.oplus.wallpapers.livephoto_wallpaper_support_hdr^^args=\"boolean:true\""
    "com.oplus.wallpapers.livephoto_wallpaper_support_4k^^args=\"boolean:true\""
    "com.oplus.gallery3d.aihd_support"
    "os.graphic.gallery.collage.asset_bounds_break^出圈^args=\"boolean:true\""
    "os.graphic.gallery.collage.livephoto^^args=\"boolean:true\""
    "com.oplus.wallpapers.3d_wallpaper^3D壁纸^args=\"boolean:true\""
    "com.oplus.aipaint^^args=\"boolean:true\""
    "com.oplus.aipaint.function_switch^^args=\"boolean:true\""
)

_xml_add_main_features_script() {
    local entry
    for entry in "${oplus_features[@]}"; do
        printf 'oplus_feature\t%s\n' "${entry}"
    done
    if [[ ${vndk_version:-0} -gt 33 ]]; then
        printf 'oplus_feature\toplus.software.radio.networkless_support^无网畅聊\n'
    fi
    for entry in "${app_features[@]}"; do
        printf 'app_feature\t%s\n' "${entry}"
    done
    if [[ "${port_oplusrom_version}" == "16.0.1" ]]; then
        printf 'app_feature\tcom.oplus.wallpapers.ai_camera_movement^^args="boolean:true"\n'
    else
        printf 'app_feature\tcom.oplus.wallpapers.ai_camera_movement_for_products_before_15^^args="boolean:true"\n'
    fi
    cat <<'EOF'
permission_oplus_feature	oplus.software.game.cold.start.speedup.enable
permission_feature	com.plus.press_power_botton_experiment
permission_feature	oplus.video.hdr10_support
permission_feature	oplus.video.hdr10plus_support
permission_feature	oppo.display.screen.gloablehbm.support
permission_feature	oppo.high.brightness.support
permission_feature	oppo.multibits.dimming.support
permission_feature	oplus.software.display.refreshrate_default_smart
EOF
    if [[ "${base_product_device}" == "OnePlus9Pro" ]]; then
        printf 'app_feature\tos.charge.settings.wirelesscharging.power^设置显示无线充电瓦数^args="int:50"\n'
        printf 'app_feature\toplus.power.wirelesschgwhenwired.support\n'
        printf 'app_feature\tcom.oplus.battery.wireless.charging.notificate\n'
        printf 'app_feature\tos.charge.settings.wirelesschargingcoil.position\n'
        printf 'app_feature\tos.charge.settings.wirelesscharge.support\n'
    elif [[ "${base_product_device}" == "OP4E3F" ]] || [[ "${base_product_device}" == "OP4E5D" ]]; then
        printf 'app_feature\tos.charge.settings.wirelesscharging.power^设置显示无线充电瓦数^args="int:30"\n'
        printf 'app_feature\toplus.power.wirelesschgwhenwired.support\n'
        printf 'app_feature\tcom.oplus.battery.wireless.charging.notificate\n'
        printf 'app_feature\tos.charge.settings.wirelesschargingcoil.position\n'
        printf 'app_feature\tos.charge.settings.wirelesscharge.support\n'
    fi
}

_xml_add_main_features_script | run_xml_tool add-features --port-dir build/portrom/images/my_product/etc --stdin
_xml_add_rc=$?
if [[ ${_xml_add_rc} -eq 127 ]]; then
    for oplus_feature in "${oplus_features[@]}"; do
        add_feature_v2 oplus_feature "$oplus_feature"
    done

    if [[ $vndk_version -gt 33 ]];then
     add_feature_v2 oplus_feature "oplus.software.radio.networkless_support^无网畅聊"
    fi

    for app_feature in "${app_features[@]}"; do
        add_feature_v2 app_feature "$app_feature"
    done

     if [[ ${port_oplusrom_version} == "16.0.1" ]];then
        add_feature_v2  app_feature  "com.oplus.wallpapers.ai_camera_movement^^args=\"boolean:true\""
     else
        add_feature_v2  app_feature  "com.oplus.wallpapers.ai_camera_movement_for_products_before_15^^args=\"boolean:true\""
    fi

    add_feature_v2 permission_oplus_feature "oplus.software.game.cold.start.speedup.enable"
    add_feature_v2 permission_feature "com.plus.press_power_botton_experiment"
    add_feature_v2 permission_feature "oplus.video.hdr10_support"
    add_feature_v2 permission_feature "oplus.video.hdr10plus_support"
    add_feature_v2 permission_feature "oppo.display.screen.gloablehbm.support"
    add_feature_v2 permission_feature "oppo.high.brightness.support"
    add_feature_v2 permission_feature "oppo.multibits.dimming.support"
    add_feature_v2 permission_feature "oplus.software.display.refreshrate_default_smart"
    if [[ "${base_product_device}" == "OnePlus9Pro" ]] ;then
        add_feature_v2 app_feature "os.charge.settings.wirelesscharging.power^设置显示无线充电瓦数^args=\"int:50\"" "oplus.power.wirelesschgwhenwired.support" "com.oplus.battery.wireless.charging.notificate" "os.charge.settings.wirelesschargingcoil.position" "os.charge.settings.wirelesscharge.support"
    elif [[ "${base_product_device}" == "OP4E3F" ]] || [[ "${base_product_device}" == "OP4E5D" ]];then
        add_feature_v2 app_feature "os.charge.settings.wirelesscharging.power^设置显示无线充电瓦数^args=\"int:30\"" "oplus.power.wirelesschgwhenwired.support" "com.oplus.battery.wireless.charging.notificate" "os.charge.settings.wirelesschargingcoil.position" "os.charge.settings.wirelesscharge.support"
    fi
elif [[ ${_xml_add_rc} -ne 0 ]]; then
    exit "${_xml_add_rc}"
fi

if [[ "${base_product_device}" != "OnePlus9Pro" && "${base_product_device}" != "OP4E3F" && "${base_product_device}" != "OP4E5D" ]]; then
    run_xml_tool remove-features \
        --port-dir build/portrom/images/my_product/etc \
        --base-dir build/baserom/images/my_product/etc \
        --feature "oplus.power.wirelesschgwhenwired.support" \
        --feature "com.oplus.battery.wireless.charging.notificate" \
        --feature "os.charge.settings.wirelesscharge.support" \
        --feature "os.charge.settings.wirelesscharging.power" \
        --feature "os.charge.settings.wirelesschargingcoil.position" \
        --feature "oplus.power.onwirelesscharger.support"
    if [[ $? -eq 127 ]]; then
        remove_feature "oplus.power.wirelesschgwhenwired.support"
        remove_feature "com.oplus.battery.wireless.charging.notificate"
        remove_feature "os.charge.settings.wirelesscharge.support"
        remove_feature "os.charge.settings.wirelesscharging.power"
        remove_feature "os.charge.settings.wirelesschargingcoil.position"
        remove_feature "oplus.power.onwirelesscharger.support"
    fi
fi

#通话录音限制
run_xml_tool delete-elements \
    --file build/portrom/images/my_stock/etc/extension/com.oplus.app-features.xml \
    --tag app_feature --attr name \
    --value com.android.incallui.support_call_record_prompt_mcc \
    --value com.android.incallui.hide_call_record_mcc
if [[ $? -eq 127 ]]; then
    xmlstarlet ed -L -d '//app_feature[@name="com.android.incallui.support_call_record_prompt_mcc"]' build/portrom/images/my_stock/etc/extension/com.oplus.app-features.xml
    xmlstarlet ed -L -d '//app_feature[@name="com.android.incallui.hide_call_record_mcc"]' build/portrom/images/my_stock/etc/extension/com.oplus.app-features.xml
fi 

#echo "ro.build.version.oplusrom=$ota_version" >> build/portrom/images/system/system/build.prop
#echo "oplus_hex_nv_id=$oplus_hex_nv_id" >> build/portrom/images/system/system/build.prop

if [[ $port_vendor_brand == "realme" ]];then
     if ensure_resource_available "devices/common/ai_memory_16.zip"; then
      unzip -qo devices/common/ai_memory_16.zip -d build/portrom/images/
     fi
fi

aimemory_app=$(find build/portrom -type f -name "AIMemory.apk")

if [[ ! -f $aimemory_app ]]; then
    
    if [[ $regionmark == "CN" ]];then 
        if ensure_resource_available "devices/common/ai_memory.zip"; then
            unzip -qo devices/common/ai_memory.zip -d build/portrom/images/
        fi
    else
         if ensure_resource_available "devices/common/ai_memory_in/aimemory.zip"; then
            unzip -qo devices/common/ai_memory_in/aimemory.zip -d build/portrom/images/
         fi
    fi
fi

for pkg in com.oplus.aimemory com.oplus.appbooster; do
    run_xml_tool upsert-element \
        --file build/portrom/images/my_product/etc/config/app_v2.xml \
        --parent app --tag enable --key-attr pkg --key-value "${pkg}" \
        --attrs "pkg=\"${pkg}\" priority=\"7\""
    if [[ $? -eq 127 ]]; then
        if ! grep -q "<enable pkg=\"$pkg\"" build/portrom/images/my_product/etc/config/app_v2.xml;then
            sed -i "/<\/app>/i\  <enable pkg=\"$pkg\" priority=\"7\"/>" build/portrom/images/my_product/etc/config/app_v2.xml
        fi
    fi
done

if [[ ! -d build/portrom/images/my_product/etc/aisubsystem ]]; then
     if [[ $regionmark != "CN" ]];then 
         if ensure_resource_available "devices/common/ai_memory_in/aisubsystem.zip"; then
            unzip -qo devices/common/ai_memory_in/aisubsystem.zip -d build/portrom/images/
         fi
     fi
fi

if [[ -d devices/common/GTMode/overlay ]] && [[ $port_android_version != "16" ]];then
    #add_feature "oplus.software.support.gt.mode" build/portrom/images/my_product/etc/permissions/oplus.feature.android.xml
    add_feature_v2 oplus_feature "oplus.software.support.gt.mode^GT模式" 
    add_feature_v2 app_feature "com.android.settings.device_rm^Realme设备，显示GT模式需要"
    #add_feature "com.oplus.battery.support.gt_open_gamecenter" build/portrom/images/my_product/etc/extension/com.oplus.app-features.xml
    if [[ $port_vendor_brand != "realme" ]];then
        cp -rf devices/common/GTMode/overlay/* build/portrom/images/
    fi
fi

if [[ $port_vendor_brand == "realme" ]] && [[ $regionmark == "CN" ]] ;then
    add_feature_v2 oplus_feature "oplus.software.support.gt.mode^GT模式" 
    add_feature_v2 app_feature "com.android.settings.device_rm^Realme设备，显示GT模式需要"
    add_feature_v2 app_feature "com.oplus.smartsidebar.space.roulette.support^AI传送门" \
            "com.oplus.smartsidebar.space.roulette.bootreg" \
            "com.coloros.support_gt_boost^^args=\"boolean:true\""
    add_feature_v2 permission_oplus_feature "oplus.software.aigc_global_drag" "oplus.software.smart_loop_drag"

    #temp
    #unzip -o devices/common/glassui_rui7.zip -d build/portrom/images/
fi

#echo "ro.surface_flinger.supports_background_blur=1" >> build/portrom/images/my_product/build.prop
#echo "ro.surface_flinger.media_panel_bg_blur=1" >> build/portrom/images/my_product/build.prop

# 强光模式选项开关
add_feature_v2 oplus_feature "oplus.software.display.manual_hbm.support"
add_prop_v2 "ro.oplus.display.sell_mode.max_normal_nit" "800"

add_feature "android.hardware.biometrics.face"  build/portrom/images/my_product/etc/permissions/android.hardware.fingerprint.xml


add_feature_v2 oplus_feature "oplus.software.display.smart_color_temperature_rhythm_health_support"

#人声突显
add_feature "oplus.hardware.audio.voice_isolation_support" build/portrom/images/my_product/etc/permissions/oplus.product.feature_multimedia_unique.xml
add_feature "oplus.hardware.audio.voice_denoise_support" build/portrom/images/my_product/etc/permissions/oplus.product.feature_multimedia_unique.xml

#旁路供电
run_xml_tool upsert-element \
    --file build/portrom/images/my_product/etc/extension/com.oplus.app-features-ext-bruce.xml \
    --parent extend_features --tag app_feature \
    --key-attr name --key-value com.oplus.plc_charge.support \
    --attrs 'name="com.oplus.plc_charge.support"' \
    --child '<StringList args="true"/>'
if [[ $? -eq 127 ]]; then
    sed -i '/<\/extend_features>/i\
    <app_feature name="com.oplus.plc_charge.support">\
        <StringList args="true"/>\
    </app_feature>' build/portrom/images/my_product/etc/extension/com.oplus.app-features-ext-bruce.xml
fi
add_feature_v2 app_feature "com.android.settings.device_rm^Realme设备"
add_feature_v2  app_feature "com.oplus.fullscene_plc_charge.support^全场景旁路充电^args=\"boolean:true\""
#三段式
if grep -q "oplus.software.audio.alert_slider"  build/portrom/images/my_product/etc/permissions/* ;then
    add_feature "oplus.software.audio.alert_slider" build/portrom/images/my_product/etc/permissions/oplus.product.feature_multimedia_unique.xml
fi

EUICC_GOOGLE=$(find build/portrom/images/ -name "EuiccGoogle" -type d -print -quit)
_remove_features_list=(
    "oplus.software.display.wcg_2.0_support"
    "oplus.software.display.origin_roundcorner_support"
    "oplus.software.vibration_ring_mute"
    "oplus.software.vibration_alarm_clock"
    "oplus.software.vibration_ringtone"
    "oplus.software.vibration_threestage_key"
    "oppo.common.support.curved.display"
    "oplus.feature.largescreen"
    "oplus.feature.largescreen.land"
    "oplus.software.audio.audioeffect_support"
    "oplus.software.audio.audiox_support"
    "oppo.breeno.three.words.support"
    "oplus.software.vibrator_qcom_lmvibrator"
    "oplus.hardware.vibrator_style_switch"
    "oplus.software.vibrator_luxunvibrator"
    "oplus.software.palmprint_non_unify"
    "oplus.software.palmprint_v1"
    "oplus.software.palmprint"
    "com.android.settings.processor_detail_gen2"
    "com.android.settings.processor_detail"
    "oplus.software.display.adfr_v32_hp"
    "com.oplus.battery.phoneusage.screenon.hide"
)
if [[ -d "${EUICC_GOOGLE}" ]]; then
    rm -rf -- "${EUICC_GOOGLE}"
    _remove_features_list+=(
        "android.hardware.telephony.euicc"
        "oplus.software.radio.esim_support_sn220u"
        "oplus.software.radio.esim_support"
        "com.android.systemui.keyguard_support_esimcard"
    )
fi

printf '%s\n' "${_remove_features_list[@]}" | run_xml_tool remove-features \
    --port-dir build/portrom/images/my_product/etc \
    --base-dir build/baserom/images/my_product/etc \
    --stdin
if [[ $? -eq 127 ]]; then
    for _rf in "${_remove_features_list[@]}"; do
        remove_feature "${_rf}"
    done
fi

cp -rf  build/baserom/images/my_product/vendor/etc/* build/portrom/images/my_product/vendor/etc/

 # Camera
 if [[ $base_android_sdk -lt 33 ]];then
    cp -rf  build/baserom/images/my_product/etc/camera/* build/portrom/images/my_product/etc/camera
    old_camera_app=$(find build/baserom/images/my_product -type f -name "OnePlusCamera.apk")
    if [[ -f $old_camera_app ]];then
        cp -rf $(dirname "$old_camera_app")* build/portrom/images/my_product/priv-app/
        if [ ! -d build/portrom/images/my_product/priv-app/etc/permissions/ ];then
            mkdir -p build/portrom/images/my_product/priv-app/etc/permissions/
        fi
        rm -rf build/portrom/images/my_product/product_overlay/framework/*
        cp -rf build/baserom/images/my_product/product_overlay/* build/portrom/images/my_product/product_overlay/
    #    find build/portrom/images/ -type f -name "*.prop" -exec  sed -i "s/ro.product.model=.*/ro.product.model=${base_market_name}/g" {} \;
    #   find build/portrom/images/ -type f -name "*.prop" -exec  grep "ro.product.model" {} \;
        cp -rf  build/baserom/images/my_product/priv-app/etc/permissions/*   build/portrom/images/my_product/priv-app/etc/permissions/
        new_camera=$(find build/portrom/images/my_product -type f -name "OplusCamera.apk")
        if [[ -f $new_camera ]]; then
            rm -rf $(dirname $new_camera)
        fi
        base_scanner_app=$(find build/baserom/images/ -type d -name "OcrScanner")                  
        target_scanner_app=$(find build/portrom/images/ -type d -name "OcrScanner")
        if [[ -n $base_scanner_app ]] && [[ -n $target_scanner_app ]];then
                blue "替换原版扫一扫" "Replacing Stock OrcScanner"
            rm -rf $target_scanner_app/*
            cp -rf $base_scanner_app $target_scanner_app
        fi
    else
        _port::restore_stock_oplus_camera || exit 1
    fi
else
    add_prop_v2 "ro.vendor.oplus.camera.isSupportExplorer" "1"
    _port::restore_stock_oplus_camera || exit 1
fi
ensure_oplus_camera_unit_sdk_permission || exit 1

if [[ ${base_device_family} == "OPSM8250" ]]; then
  camera_optimize_file=$(find build/portrom/images/ -type f -name "sys_camera_optimize_config.xml")
  # Fix wechat /alipay scan crash issue
   if [[ -f $camera_optimize_file ]]; then
      rm -f $camera_optimize_file
   fi
fi

sourceOvoiceManagerService=$(find build/baserom/images/my_product -type d -name "OVoiceManagerService")
if [[ -d "$sourceOvoiceManagerService" ]];then
    targetOvoiceManagerService=$(find build/portrom/images/my_product -type d -name "OVoiceManagerService")
    if [[ -d "$targetOvoiceManagerService" ]];then
       # rm -rfv $targetOvoiceManagerService/* 
        cp -rf $sourceOvoiceManagerService/* $targetOvoiceManagerService/
    else
        cp -rf $sourceOvoiceManagerService build/portrom/images/my_product/priv-app/
    fi
fi

if [[ ${base_product_device} == "OnePlus8T" ]];then 
    # Voice_trigger for OnePlus 8T
    add_feature_v2 oplus_feature "oplus.software.audio.voice_wakeup_support^旧版语音唤醒" "oplus.software.audio.voice_wakeup_3words_support"
    #add_feature "oplus.software.speechassist.oneshot.support" build/portrom/images/my_product/etc/extension/com.oplus.oplus-feature.xml
    if ensure_resource_available "${work_dir}/devices/common/voice_trigger_fix.zip"; then
        unzip -qo ${work_dir}/devices/common/voice_trigger_fix.zip -d ${work_dir}/build/portrom/images/
    fi
fi


cp -rf build/baserom/images/my_product/etc/Multimedia_*.xml build/portrom/images/my_product/etc/


if [[ -f "tmp/etc/permissions/multimedia_privapp-permissions-oplus.xml" ]];then
    cp -rf tmp/etc/permissions/multimedia_*.xml build/portrom/images/my_product/etc/permissions/
fi



for file in $(find build/baserom/images/my_product/etc/ -type f -name "OVMS_*");do
    if [[ -f "$file" ]];then
        cp -rf $file build/portrom/images/my_product/etc/
    fi
done
#fix chinese char
run_rom_ops strip-non-ascii --dir build/portrom/images/config --name "*file_contexts"
if [[ $? -eq 127 ]]; then
    find build/portrom/images/config -type f -name "*file_contexts" \
        -exec perl -i -ne 'print if /^[\x00-\x7F]+$/' {} \;
fi
#find build/portrom/images/config -type f -name "*file_contexts" -exec sed -i -E '/[\x{4e00}-\x{9fa5}]/d' {} \;

# bootanimation
if [[ $baseIsOOS == "true" && $portIsOOS == "true" ]]; then
    rm -rf build/portrom/images/my_product/media/bootanimation
    cp -rf build/baserom/images/my_product/media/bootanimation build/portrom/images/my_product/media/
elif [[ $baseIsColorOSCN == "true" && ( $portIsColorOSGlobal == "true" || $portIsColorOS == "true" ) ]]; then
    rm -rf build/portrom/images/my_product/media/bootanimation
    cp -rf build/baserom/images/my_product/media/bootanimation build/portrom/images/my_product/media/
fi
 
rm -rf build/portrom/images/my_product/media/quickboot
cp -rf build/baserom/images/my_product/media/quickboot build/portrom/images/my_product/media/
if ensure_resource_available "devices/common/wallpaper.zip" && [[ "$portIsColorOSGlobal" == "false" ]] && [[ "$portIsOOS" == "false" ]] && [[ "$port_android_version" -lt 16 ]];then
    unzip -qo devices/common/wallpaper.zip -d build/portrom/images
 fi   

rm -rf build/portrom/images/my_product/res/*
cp -rf build/baserom/images/my_product/res/* build/portrom/images/my_product/res/

#rm -rf build/portrom/images/my_product/vendor/*
cp -rf build/baserom/images/my_product/vendor/* build/portrom/images/my_product/vendor/
rm -rf  build/portrom/images/my_product/overlay/*display*[0-9]*.apk
for overlay in $(find build/baserom/images/ -type f -name "*${base_my_product_type}*".apk);do
    cp -rf $overlay build/portrom/images/my_product/overlay/
done

super_computing=$(find build/portrom/images/my_product -name "string_super_computing*" -print -quit)
if [[ -z "${super_computing}" || ! -f "${super_computing}" ]] && [[ -d devices/common/super_computing ]]; then
    mkdir -p build/portrom/images/my_product/etc/
    cp -rf devices/common/super_computing/* build/portrom/images/my_product/etc/
fi

baseCarrierConfigOverlay=$(find build/baserom/images/ -type f -name "CarrierConfigOverlay*.apk" -print -quit)
portCarrierConfigOverlay=$(find build/portrom/images/ -type f -name "CarrierConfigOverlay*.apk" -print -quit)
if [ -f "${baseCarrierConfigOverlay}" ] && [ -f "${portCarrierConfigOverlay}" ];then
    blue "正在替换 [CarrierConfigOverlay.apk]" "Replacing [CarrierConfigOverlay.apk]"
    rm -rf "${portCarrierConfigOverlay}"
    cp -rf "${baseCarrierConfigOverlay}" "$(dirname "${portCarrierConfigOverlay}")"
elif [ -f "${baseCarrierConfigOverlay}" ]; then
    cp -rf "${baseCarrierConfigOverlay}" build/portrom/images/my_product/overlay/
fi



#add_feature "oplus.software.display.eyeprotect_paper_texture_support" build/portrom/images/my_product/etc/extension/com.oplus.oplus-feature.xml

add_feature "oplus.software.display.reduce_brightness_rm" build/portrom/images/my_product/etc/permissions/oplus.product.feature_multimedia_unique.xml
add_feature "oplus.software.display.reduce_brightness_rm_manual" build/portrom/images/my_product/etc/permissions/oplus.product.feature_multimedia_unique.xml

add_feature "oplus.software.display.brightness_memory_rm" build/portrom/images/my_product/etc/permissions/oplus.product.feature_multimedia_unique.xml
add_feature "oplus.software.display.sec_max_brightness_rm" build/portrom/images/my_product/etc/permissions/oplus.product.feature_multimedia_unique.xml

_display_props_batch() {
    cat <<'EOF'
persist.lowbrightnessthreshold=0
persist.sys.renderengine.maxLuminance=500
ro.oplus.display.peak.brightness.duration_time=15
ro.oplus.display.peak.brightness.effect_interval_time=1800000
ro.oplus.display.peak.brightness.effect_times_every_day=2
ro.display.brightness.thread.priority=true
ro.oplus.audio.speaker_clean=true
ro.vendor.oplus.radio.use_nitz_name=true
EOF
    if [[ $regionmark == "CN" ]]; then
        printf 'ro.oplus.display.brightness.min_settings.rm=1,1,25,4.0,0\n'
    fi
}
_display_props_batch | run_prop_tool batch \
    --file build/portrom/images/my_product/build.prop \
    --bruce-file build/portrom/images/my_product/etc/bruce/build.prop \
    --base build/baserom/images/my_product/build.prop \
    --stdin
_display_props_rc=$?
if [[ ${_display_props_rc} -eq 127 ]]; then
    add_prop_v2 "persist.lowbrightnessthreshold" "0"
    add_prop_v2 "persist.sys.renderengine.maxLuminance" "500"
    add_prop_v2 "ro.oplus.display.peak.brightness.duration_time" "15"
    add_prop_v2 "ro.oplus.display.peak.brightness.effect_interval_time" "1800000"
    add_prop_v2 "ro.oplus.display.peak.brightness.effect_times_every_day" "2"
    add_prop_v2 "ro.display.brightness.thread.priority" "true"
    add_prop_v2 "ro.oplus.audio.speaker_clean" "true"
    add_prop_v2 "ro.vendor.oplus.radio.use_nitz_name" "true"
    if [[ $regionmark == "CN" ]]; then
        add_prop_v2 "ro.oplus.display.brightness.min_settings.rm" "1,1,25,4.0,0"
    fi
elif [[ ${_display_props_rc} -ne 0 ]]; then
    exit "${_display_props_rc}"
fi

if [[ ${base_product_device} == "OnePlus8Pro" ]] ;then 
    if [[ ${port_android_version} -gt 15 ]];then
            {
    echo "# OnePlus8Pro移除属性"
    echo "ro.display.brightness.hbm_xs="
    echo "ro.display.brightness.hbm_xs_min="
    echo "ro.display.brightness.hbm_xs_max="
    echo "ro.oplus.display.brightness.xs="
    echo "ro.oplus.display.brightness.ys="
    echo "ro.oplus.display.brightness.hbm_ys="
    echo "ro.oplus.display.brightness.default_brightness="
    echo "ro.oplus.display.brightness.normal_max_brightness="
    echo "ro.oplus.display.brightness.max_brightness="
    echo "ro.oplus.display.brightness.normal_min_brightness="
    echo "ro.oplus.display.brightness.min_light_in_dnm="
    echo "ro.oplus.display.brightness.smooth="
    echo "ro.display.brightness.mode.exp.per_20="
    echo "ro.vendor.display.AIRefreshRate.brightness="
    echo "ro.oplus.display.dwb.threshold="
    echo "ro.oplus.display.dynamic.dither="
    echo "persist.oplus.display.initskipconfig="

} >> build/portrom/images/my_product/etc/bruce/build.prop
    fi
fi


if [[ -d build/baserom/images/my_product/etc/vibrator ]];then
    rm -rf build/portrom/images/my_product/etc/vibrator
    cp -rf build/baserom/images/my_product/etc/vibrator build/portrom/images/my_product/etc/
fi


if [[ $base_device_family == "OPSM8350" ]]; then
    if ensure_resource_available "devices/common/aon_fix_sm8350.zip"; then
        rm -rf build/portrom/images/my_product/overlay/aon*.apk
        unzip -qo devices/common/aon_fix_sm8350.zip -d build/portrom/images/
    fi

elif [[ $base_device_family == "OPSM8250" ]]; then
    if ensure_resource_available "devices/common/aon_fix_sm8250.zip"; then
        rm -rf build/portrom/images/my_product/overlay/aon*.apk
        unzip -qo devices/common/aon_fix_sm8250.zip -d build/portrom/images/
    fi
else

    sourceAONService=$(find build/baserom/images/my_product -type d -name "AONService")

    if [[ -d "$sourceAONService" ]];then
        targetAONService=$(find build/portrom/images/my_product -type d -name "AONService")
        if [[ -d "$targetAONService" ]];then
            rm -rf $targetAONService/* 
            cp -rf $sourceAONService/* $targetAONService/
        else
            cp -rf $sourceAONService build/portrom/images/my_product/app/
        fi
        
        add_feature "oplus.software.aon_pay_qrcode_enable" build/portrom/images/my_product/etc/extension/com.oplus.oplus-feature.xml
        remove_feature "oplus.software.aon_sensorhub_enable" 

    fi
    if ! compgen -G "build/baserom/images/my_product/overlay/aon*.apk" >/dev/null && [[ $regionmark == "CN" ]];then
        rm -rf build/portrom/images/my_product/overlay/aon*.apk
    fi
fi
#Realme隔空手势 CN限定
if ensure_resource_available "devices/common/realme_gesture.zip" && [[ "$port_vendor_brand" != "realme" ]] && [[ $port_android_version -lt "16" ]];then
    unzip -qo devices/common/realme_gesture.zip -d build/portrom/images/
    sed -i "s/ro.camera.privileged.3rdpartyApp=.*/ro.camera.privileged.3rdpartyApp=com.aiunit.aon\;com.oplus.gesture\;/g" build/portrom/images/my_stock/build.prop
fi


if [[ "${PORT_USE_STOCK_CAMERA:-false}" != "true" ]] && { [[ "${base_product_device}" == "OnePlus9Pro" ]] || [[ "${base_product_device}" == "OnePlus9" ]] || [[ "${base_product_device}" == "OP4E5D" ]] || [[ "${base_product_device}" == "OP4E3F" ]]; }; then
    if [[ "$portIsColorOS" == "true" ]];then
        if [[ $port_android_version == "17" ]];then
            if ensure_resource_available "devices/common/camera6.0-fix_cos.zip"; then
                blue "ColorOS17 相机修复" "ColorOS17 Camera Fix"
                rm -rf build/portrom/images/my_product/app/OplusCamera
                rm -rf build/portrom/images/my_product/product_overlay/framework/com.oplus.camera.*.jar
                echo "ro.vendor.oplus.camera.isSupportLumo=1" >> build/portrom/images/my_product/etc/bruce/build.prop
                unzip -qo devices/common/camera6.0-fix_cos.zip -d build/portrom/images/
                if ensure_resource_available "devices/${base_product_device}/camera6.0-fix_odm.zip"; then
                    unzip -qo devices/${base_product_device}/camera6.0-fix_odm.zip -d build/portrom/images/
                else
                    unzip -qo devices/${base_product_device}/camera5.0-fix_odm.zip -d build/portrom/images/
                fi
            fi
        elif [[ $port_android_version == "16" ]];then
            if ensure_resource_available "devices/common/camera6.0-fix_cos.zip"; then
                blue "ColorOS16 相机修复" "ColorOS16 Camera Fix"
                rm -rf build/portrom/images/my_product/app/OplusCamera
                rm -rf build/portrom/images/my_product/product_overlay/framework/com.oplus.camera.*.jar
                echo "ro.vendor.oplus.camera.isSupportLumo=1" >> build/portrom/images/my_product/etc/bruce/build.prop
                unzip -qo devices/common/camera6.0-fix_cos.zip -d build/portrom/images/
                if ensure_resource_available "devices/${base_product_device}/camera6.0-fix_odm.zip"; then
                    unzip -qo devices/${base_product_device}/camera6.0-fix_odm.zip -d build/portrom/images/
                else
                    unzip -qo devices/${base_product_device}/camera5.0-fix_odm.zip -d build/portrom/images/
                fi
            fi
        elif [[ $port_android_version -ge "15" ]];then
            if ensure_resource_available "devices/${base_product_device}/camera5.0-fix_cos.zip"; then
                blue "ColorOS15 相机修复" "ColorOS15 Camera Fix"
                rm -rf build/portrom/images/my_product/app/OplusCamera
                rm -rf build/portrom/images/my_product/product_overlay/framework/com.oplus.camera.*.jar
                echo "ro.vendor.oplus.camera.isSupportLumo=1" >> build/portrom/images/my_product/etc/bruce/build.prop
                unzip -qo devices/${base_product_device}/camera5.0-fix_cos.zip -d build/portrom/images/
                if ensure_resource_available "devices/${base_product_device}/camera5.0-fix_odm.zip"; then
                    unzip -qo devices/${base_product_device}/camera5.0-fix_odm.zip -d build/portrom/images/
                fi
            fi
        else
            blue "添加实况照片拍摄支持" "Live Photo support"
            rm -rf build/portrom/images/my_product/app/OplusCamera
            rm -rf build/portrom/images/my_product/product_overlay/framework/com.oplus.camera.*.jar
            if ensure_resource_available "devices/${base_product_device}/live_photo_adds.zip"; then
                unzip -qo devices/${base_product_device}/live_photo_adds.zip -d build/portrom/images/
            fi
        fi
    elif  [[ "$portIsColorOSGlobal" == "true" ]];then
        if ensure_resource_available "devices/${base_product_device}/camera5.0-fix_cos_global.zip"; then
            blue "ColorOS Global 15 相机修复" "ColorOS15 Global Camera Fix"
            rm -rf build/portrom/images/my_product/app/OplusCamera
            rm -rf build/portrom/images/my_product/product_overlay/framework/com.oplus.camera.*.jar
            echo "ro.vendor.oplus.camera.isSupportLumo=1" >> build/portrom/images/my_product/etc/bruce/build.prop
            unzip -qo devices/${base_product_device}/camera5.0-fix_cos_global.zip -d build/portrom/images/
            if ensure_resource_available "devices/${base_product_device}/camera5.0-fix_odm.zip"; then
                unzip -qo devices/${base_product_device}/camera5.0-fix_odm.zip -d build/portrom/images/
            fi
        fi

    elif  [[ "$portIsOOS" == "true" ]];then
        if ensure_resource_available "devices/${base_product_device}/camera5.0-fix_oos.zip"; then
            blue "OxygenOS15 相机修复" "OxygenOS 15 Camera Fix"
            rm -rf build/portrom/images/my_product/app/OplusCamera
            rm -rf build/portrom/images/my_product/product_overlay/framework/com.oplus.camera.*.jar
            echo "ro.vendor.oplus.camera.isSupportLumo=1" >> build/portrom/images/my_product/etc/bruce/build.prop
            unzip -qo devices/${base_product_device}/camera5.0-fix_oos.zip -d build/portrom/images/
            if ensure_resource_available "devices/${base_product_device}/camera5.0-fix_odm.zip"; then
                unzip -qo devices/${base_product_device}/camera5.0-fix_odm.zip -d build/portrom/images/
            fi
        fi
    fi
fi
#高能户外模式
add_prop_v2 "ro.oplus.ridermode.support_feature_switch" "11"

#解锁朋友圈动态图
if [[ -f build/portrom/images/system_ext/etc/Multimedia_Daemon_List.xml ]]; then
    run_xml_tool update-text \
        --file build/portrom/images/system_ext/etc/Multimedia_Daemon_List.xml \
        --parent wechat-livephoto --match-tag name --match-text com.tencent.mm \
        --target-tag attribute --value all
    if [[ $? -eq 127 ]]; then
        cp -rf build/portrom/images/system_ext/etc/Multimedia_Daemon_List.xml tmp/
        xmlstarlet ed -u '//wechat-livephoto/name[text()="com.tencent.mm"]/following-sibling::attribute[1]' -v "all" tmp/Multimedia_Daemon_List.xml > build/portrom/images/system_ext/etc/Multimedia_Daemon_List.xml
    fi
fi

# Fix atfwd@2.0.policy 
atfwd_policy_file=$(find build/portrom/images/vendor/ -name "atfwd@2.0.policy" -print -quit)

if [ -n "$atfwd_policy_file" ]; then
  echo "Found policy file: $atfwd_policy_file"
  for prop in getid gettid setpriority; do
    if ! grep -q "${prop}: 1" "$atfwd_policy_file"; then
      echo "${prop}: 1" >> "$atfwd_policy_file"
    else
      blue "⚙️  Already contains ${prop}: 1"
    fi
  done
else
  blue "❌ No atfwd@2.0.policy found."
fi

if  [[ "${base_product_device}" == "OnePlus9Pro" ]] ||[[ "${base_product_device}" == "OnePlus9" ]];then
    echo -e "\n[FeatureTorch]\n    isSupportTorchStrengthLevel = TRUE\n    maxStrengthLevel = 4\n    defaultStrengthLevel = 4\n " >> build/portrom/images/odm/etc/camera/CameraHWConfiguration.config
fi

if [[ ${port_android_version} == 16 ]] && [[ ${base_android_version} -lt 15 ]];then
    rm -rf build/portrom/images/system_ext/priv-app/com.qualcomm.location
    #remove_feature "oplus.software.display.dcbacklight_support" force
if ensure_resource_available "devices/common/nfc_fix_a16_v2.zip"; then
    rm -rf build/portrom/images/system/system/priv-app/NfcNci/*
    unzip -qo devices/common/nfc_fix_a16_v2.zip -d ${work_dir}/build/portrom/images/
fi
    if ensure_resource_available "devices/common/wifi_fix_a16.zip" && [[ $regionmark == "CN" ]];then
    unzip -qo devices/common/wifi_fix_a16.zip -d ${work_dir}/build/portrom/images/
    rm -rf build/portrom/images/system/system/apex/com.google.android.wifi*.apex
    fi
    if [[ ${port_oplusrom_version} == "16.0.1" ]] && [[ $regionmark != "CN" ]] ;then
        if ensure_resource_available "devices/common/oos_1601_fix.zip"; then
            unzip -qo devices/common/oos_1601_fix.zip -d build/portrom/images/
        fi
    fi

    if [[ -f build/portrom/images/my_product/cust/CN/etc/power_profile/power_profile.xml ]];then
        cp -rf build/portrom/images/odm/etc/power_profile/power_profile.xml build/portrom/images/my_product/cust/CN/etc/power_profile/
    fi

    #camera fix
    echo "vendor.audio.c2.preferred=true" >> build/portrom/images/vendor/build.prop
    echo "vendor.audio.hdr.record.enable=false" >> build/portrom/images/vendor/build.prop
    if [[ $base_product_device == "OP4E3F" ]];then
        # Fix Find X3 Pro brightness
        sed -i "/ro.oplus.display.brightness.apollo*/d" build/portrom/images/my_product/build.prop
        sed -i "/persist.brightness.apollo/d" build/portrom/images/my_product/build.prop
        rm -rf build/portrom/images/my_product/vendor/etc/display_apollo_list.xml
    fi
fi

# Android 17 + legacy vendor post-boot compatibility fixes and
# a17_patch_vendor_context_file live in functions.sh (_port::stage_postdata_compat).

if ensure_resource_available "devices/common/hdr_fix.zip" && [[ $base_android_version -le 14 ]];then
    unzip -qo devices/common/hdr_fix.zip -d build/portrom/images/
    echo "persist.sys.feature.uhdr.support=true" >> build/portrom/images/my_product/etc/bruce/build.prop
fi


#自定义替换


#Devices/机型代码/overlay 按照镜像的目录结构，可直接替换目标。

if [[ -d "devices/common/overlay" ]]; then
    cp -rf  devices/common/overlay/* build/portrom/images/
fi

if [[ -d "devices/${base_product_device}/overlay" ]]; then
    cp -rf  devices/${base_product_device}/overlay/* build/portrom/images/
else
    yellow "devices/${base_product_device}/overlay 未找到" "devices/${base_product_device}/overlay not found" 
fi

if ensure_resource_available "devices/${base_product_device}/odm_selinux_fix_a16.zip" && [[ $port_android_version == 16 || $port_android_version == 17 ]]; then
    unzip -qo devices/${base_product_device}/odm_selinux_fix_a16.zip -d ${work_dir}/build/portrom/images/
fi

anykernel_device_dir="${work_dir}/devices/${base_product_device}"
_port::clear_anykernel_outputs "${anykernel_device_dir}" || exit 1

# Kernel integration is opt-in.  A stale boot_ksu/boot_noksu artifact from an
# earlier run must never be selected when enable_ksu is false.
if [[ "${enable_ksu}" == "true" ]]; then
    blue "启用 KernelSU 支持..." "Enabling KernelSU support..."
    mkdir -p "${work_dir}/tmp" "${anykernel_device_dir}" || exit 1
    rm -rf -- \
        "${work_dir}/tmp/anykernel" \
        "${work_dir}/tmp/anykernel-ksu" \
        "${work_dir}/tmp/anykernel-noksu"

    while IFS= read -r -d '' zip; do
        if unzip -l "${zip}" | grep -q "anykernel.sh"; then
            blue "检查到第三方内核压缩包 ${zip} [AnyKernel类型]" "Custom Kernel zip ${zip} detected [Anykernel]"
            anykernel_variant="$(_port::anykernel_variant_for_zip "${zip}")"
            if ! unzip -qo "${zip}" -d "${work_dir}/tmp/anykernel-${anykernel_variant}" > /dev/null 2>&1; then
                yellow "AnyKernel 压缩包解压失败，跳过 ${zip}" "Failed to extract AnyKernel archive; skipping ${zip}"
                rm -rf -- "${work_dir}/tmp/anykernel-${anykernel_variant}"
            fi
        fi
    done < <(find "${work_dir}/devices/${base_product_device}/" -type f -name "*.zip" -print0)

    for anykernel_dir in \
        "${work_dir}/tmp/anykernel" \
        "${work_dir}/tmp/anykernel-ksu" \
        "${work_dir}/tmp/anykernel-noksu"; do
        if [[ -d "${anykernel_dir}" ]]; then
            blue "开始整合第三方内核进boot.img" "Start integrating custom kernel into boot.img"
            kernel_file=$(find "${anykernel_dir}" -type f -name "Image" -print -quit)
            dtb_file=$(find "${anykernel_dir}" -type f -name "dtb" -print -quit)
            dtbo_img=$(find "${anykernel_dir}" -type f -name "dtbo.img" -print -quit)
            if [[ -z "${kernel_file}" || ! -f "${kernel_file}" ]]; then
                yellow "AnyKernel 压缩包缺少 Image，跳过内核整合" "AnyKernel archive has no Image; skipping kernel integration"
                rm -rf -- "${anykernel_dir}"
                continue
            fi
            if [[ "${anykernel_dir}" == *"-ksu" ]]; then
                [[ -f "${dtbo_img}" ]] && cp -f -- "${dtbo_img}" "${anykernel_device_dir}/dtbo_ksu.img"
                patch_kernel "${kernel_file}" "${dtb_file}" "boot_ksu.img"
                blue "生成内核boot_ksu.img完毕" "New boot_ksu.img generated"
            elif [[ "${anykernel_dir}" == *"-noksu" ]]; then
                [[ -f "${dtbo_img}" ]] && cp -f -- "${dtbo_img}" "${anykernel_device_dir}/dtbo_noksu.img"
                patch_kernel "${kernel_file}" "${dtb_file}" "boot_noksu.img"
                blue "生成内核boot_noksu.img" "New boot_noksu.img generated"
            else
                [[ -f "${dtbo_img}" ]] && cp -f -- "${dtbo_img}" "${anykernel_device_dir}/dtbo_custom.img"
                patch_kernel "${kernel_file}" "${dtb_file}" "boot_custom.img"
                blue "生成内核boot_custom.img完毕" "New boot_custom.img generated"
            fi
        fi
        [[ -d "${anykernel_dir}" ]] && rm -rf -- "${anykernel_dir}"
    done

    # Determine the target image and KMI before invoking the modern KSU
    # helpers.  They perform their own unpack/repack checks and leave the
    # original image untouched on failure.
    ksu_target_img=""
    if [[ -f "${work_dir}/build/baserom/images/init_boot.img" ]]; then
        ksu_target_img="${work_dir}/build/baserom/images/init_boot.img"
    elif [[ -f "${work_dir}/build/baserom/images/boot.img" ]]; then
        ksu_target_img="${work_dir}/build/baserom/images/boot.img"
    elif [[ -f "${work_dir}/build/baserom/boot.img" ]]; then
        ksu_target_img="${work_dir}/build/baserom/boot.img"
    fi

    if [[ -z "${ksu_target_img}" ]]; then
        yellow "未找到 init_boot.img 或 boot.img，跳过 KSU 修补" "Neither init_boot.img nor boot.img found, skipping KSU patch"
    else
        if [[ -z "${kmi:-}" ]]; then
            kmi=""
            while IFS= read -r prop; do
                kernel_id=$(grep -E '^ro.build.kernel.id=' "${prop}" | cut -d= -f2)
                [[ -n "${kernel_id}" ]] && break
            done < <(find "${work_dir}/build/portrom/images" -type f -name "build.prop")
            kernel_major=$(printf '%s' "${kernel_id:-}" | grep -Eo '^[0-9]+\.[0-9]+' || true)
            case "${kernel_major}" in
                6.1)  kmi="android14-6.1" ;;
                6.6)  kmi="android15-6.6" ;;
                6.12) kmi="android16-6.12" ;;
            esac
        fi
        if [[ -z "${kmi}" ]] && analyze_kmi_from_boot "${ksu_target_img}"; then
            kmi="${PORT_KMI_RESULT:-}"
        fi
        if [[ -z "${kmi}" ]]; then
            yellow "无法确定 KMI 版本，跳过 KSU 修补" "Could not determine KMI version, skipping KSU patch"
        elif ! is_kmi_ksu_supported "${kmi}"; then
            yellow "KMI ${kmi} 不支持 KernelSU，跳过 KSU 集成" "KMI ${kmi} does not support KernelSU; skipping integration"
        elif prepare_ksu_assets "${kmi}" && apply_ksu_patch "${ksu_target_img}" "${kmi}"; then
            green "KernelSU 集成成功" "KernelSU integration successful"
            if [[ "${ksu_target_img}" == *"/init_boot.img" ]]; then
                cp -f -- "${ksu_target_img}" "${work_dir}/build/baserom/images/init_boot-kernelsu.img"
            fi
        else
            yellow "KSU 资源准备或补丁应用失败，跳过 KSU 集成" "KSU assets or patch failed; skipping integration"
        fi
    fi
fi

# If an externally built, locally authorized TEE-simulator payload is present,
# materialize it before image repacking.  The public clone intentionally does
# not ship that binary payload; absent assets are a clean no-op.
if ! _port::stage_patch_teesim; then
    error "TEE simulator 集成失败" "TEE simulator integration failed"
    exit 1
fi

# Preinstall requested user/system applications (Via Browser, Google Play Store,
# KernelSU Manager) before filesystem optimizations and metadata generation.
if ! _port::install_preinstalled_apps; then
    error "预装应用集成失败" "Preinstalled app integration failed"
    exit 1
fi

# Apply runtime VM/I/O/USAP optimizations and camera library permission guards
# before post-data compatibility and filesystem metadata generation.
if ! _port::stage_rom_optimizations; then
    error "ROM 运行时性能优化失败" "ROM runtime optimization stage failed"
    exit 1
fi

# Apply the remaining Android 16/17 post-data compatibility fixes from the
# optimized pipeline while staying inside the remote monolithic flow.  This
# stage is intentionally placed after device overlays and before fspatch/
# contextpatch/repack so all generated metadata sees the final file tree.
if ! _port::stage_postdata_compat; then
    error "Android 16/17 开机后兼容修复失败" "Android 16/17 post-data compatibility fixes failed"
    exit 1
fi

# Fix invalid framework color attributes after all device overlays and APK
# rebuilds, before filesystem metadata generation. Keep SystemUI's signature.
if ! _port::stage_systemui_color_compat; then
    error "SystemUI 颜色兼容修复失败" "SystemUI color compatibility fix failed"
    exit 1
fi

# Android 17 Qualcomm HIDL ports optionally use the common VNDK-30 IMS APK.
# The helper is gated by the extracted VINTF declarations and is a no-op when
# the release asset is unavailable or the target already exposes AIDL IMS.
if ! _port::patch_ims_stack_for_vndk30; then
    error "IMS 兼容修复失败" "IMS compatibility patch failed"
    exit 1
fi

# Keep the platform-specific SELinux fixes in the same monolithic repack
# boundary. They are type-gated and no-op for unrelated devices; when a host
# secilc is available they also refresh the ODM precompiled policy blobs.
if ! _port::patch_performance_sepolicy; then
    error "性能 HAL SELinux 修复失败" "Performance HAL SELinux fix failed"
    exit 1
fi
if ! _port::patch_display_panel_sepolicy; then
    error "显示面板 SELinux 修复失败" "Display panel SELinux fix failed"
    exit 1
fi

#添加erofs文件系统fstab
# if [ ${pack_type} == "EROFS" ];then
#     yellow "检查 vendor fstab.qcom是否需要添加erofs挂载点" "Validating whether adding erofs mount points is needed."
#     if ! grep -q "erofs" build/portrom/images/vendor/etc/fstab.qcom ; then
#                for pname in system odm vendor product mi_ext system_ext; do
#                      sed -i "/\/${pname}[[:space:]]\+ext4/{p;s/ext4/erofs/;s/ro,barrier=1,discard/ro/;}" build/portrom/images/vendor/etc/fstab.qcom
#                      added_line=$(sed -n "/\/${pname}[[:space:]]\+erofs/p" build/portrom/images/vendor/etc/fstab.qcom)
#                     if [ -n "$added_line" ]; then
#                         yellow "添加$pname" "Adding mount point $pname"
#                     else
#                         error "添加失败，请检查" "Adding faild, please check."
#                         exit 1
                        
#                     fi
#                 done
#     fi
# fi

# data 加密
# Use the already parsed, comment-safe configuration value instead of reading
# the file again with grep (which could accidentally match a commented line).
remove_data_encrypt="${remove_data_encryption}"
if [[ ${remove_data_encrypt} == "true" ]];then
    DECRYPTRD="-DECRYPTED"
    blue "去除data加密"
    if _prop_bin="$(_port::resolve_rust_bin prop-tool)" || _prop_bin="$(_port::resolve_rust_bin coloros-tools)"; then
        while IFS= read -r -d '' fstab; do
            blue "Target: $fstab"
            if [[ "${_prop_bin}" == *coloros-tools* ]]; then
                "${_prop_bin}" prop-tool clean-fstab --fstab "${fstab}" --remove-encryption || exit 1
            else
                "${_prop_bin}" clean-fstab --fstab "${fstab}" --remove-encryption || exit 1
            fi
        done < <(find build/portrom/images -type f -name "fstab.*" -print0)
    else
        while IFS= read -r -d '' fstab; do
            blue "Target: $fstab"
            sed -i "s/,fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0//g" "${fstab}"
            sed -i "s/,fileencryption=aes-256-xts:aes-256-cts:v2+emmc_optimized+wrappedkey_v0//g" "${fstab}"
            sed -i "s/,fileencryption=aes-256-xts:aes-256-cts:v2//g" "${fstab}"
            sed -i "s/,metadata_encryption=aes-256-xts:wrappedkey_v0//g" "${fstab}"
            sed -i "s/,fileencryption=aes-256-xts:wrappedkey_v0//g" "${fstab}"
            sed -i "s/,metadata_encryption=aes-256-xts//g" "${fstab}"
            sed -i "s/,fileencryption=aes-256-xts//g" "${fstab}"
            sed -i "s/,fileencryption=ice//g" "${fstab}"
            sed -i "s/fileencryption/encryptable/g" "${fstab}"
        done < <(find build/portrom/images -type f -name "fstab.*" -print0)
    fi
fi

# for pname in ${port_partition};do
#     rm -rf build/portrom/images/${pname}.img
# done
echo "${pack_type}">fstype.txt
if [[ $super_extended == true ]];then
    superSize=$(bash bin/getSuperSize.sh "others") || exit 1
elif [[ $base_product_model == "KB2000" ]] && [[ "$is_ab_device" == false ]] ; then
    # OnePlus 8T A-only ROM
    grep -qF 'ro.product.cpuinfo=SM8250' build/portrom/images/my_manifest/build.prop 2>/dev/null || \
        echo 'ro.product.cpuinfo=SM8250' >> build/portrom/images/my_manifest/build.prop
    superSize=$(bash bin/getSuperSize.sh OnePlus9R) || exit 1
elif [[ $base_product_model == "LE2101" ]]; then
    # "9R IN"
    superSize=$(bash bin/getSuperSize.sh OnePlus8T) || exit 1
else
    superSize=$(bash bin/getSuperSize.sh "${base_product_device}") || exit 1
fi

green "Super大小为${superSize}" "Super image size: ${superSize}"
# Device overlays may reintroduce this app after donor debloat.
rm -rf -- "${work_dir}/build/portrom/images/my_product/app/AudioEffectCenter" || exit 1
port_apply_bluetooth_display_overrides "${work_dir}/build/portrom/images" || {
    error "蓝牙/显示属性更新失败" "Failed to apply Bluetooth/display overrides"
    exit 1
}
# The provider check must see the final partition contents after all overlays.
python3 bin/webview_compat.py "${work_dir}/build/portrom/images" || exit 1
green "开始打包镜像" "Packing img"
port_pack_images ${super_list} || exit 1


rm -f -- fstype.txt

if [[ ${port_vendor_brand} == "realme" ]];then
    os_type="RealmeUI"
else
    os_type="ColorOS"
fi
rom_version=$(cat build/portrom/images/my_manifest/build.prop | grep "ro.build.display.id=" |  awk 'NR==1' | cut -d "=" -f2 | cut -d "(" -f1)
_vbmeta_imgs=()
while IFS= read -r -d '' img; do
    blue "vbmeta验证禁用： $img" "Disable vbmeta verify: $img"
    _vbmeta_imgs+=("${img}")
done < <(find build/baserom/ -type f -name "vbmeta*.img" -print0)
if [[ ${#_vbmeta_imgs[@]} -gt 0 ]]; then
    run_rom_ops patch-vbmeta "${_vbmeta_imgs[@]}" >/dev/null 2>&1
    _vbmeta_rc=$?
    if [[ ${_vbmeta_rc} -eq 127 ]]; then
        for img in "${_vbmeta_imgs[@]}"; do
            python3 bin/patch-vbmeta.py "${img}" > /dev/null 2>&1
        done
    elif [[ ${_vbmeta_rc} -ne 0 ]]; then
        exit "${_vbmeta_rc}"
    fi
fi
if [[ -f devices/${base_product_device}/recovery.img ]]; then
  cp -rf devices/${base_product_device}/recovery.img build/baserom/images/
fi

if [[ -f devices/${base_product_device}/vendor_boot.img ]]; then
  cp -rf devices/${base_product_device}/vendor_boot.img build/baserom/images/
fi

if [[ -f devices/${base_product_device}/abl.img ]]; then
  cp -rf devices/${base_product_device}/abl.img build/portrom/images/
fi

if [[ -f devices/${base_product_device}/odm.img ]]; then
  cp -rf devices/${base_product_device}/odm.img build/portrom/images/
fi

if [[ -f devices/${base_product_device}/tz.img ]]; then
  cp -rf devices/${base_product_device}/tz.img build/baserom/images/
fi

if [[ -f devices/${base_product_device}/keymaster.img ]]; then
  cp -rf devices/${base_product_device}/keymaster.img build/baserom/images/
fi

if [[ $is_ab_device == true ]]; then
    if [[ ! -f build/portrom/images/my_preload.img ]];then
        cp -rf devices/common/my_preload_empty.img build/portrom/images/my_preload.img
    fi
    if [[ ! -f build/portrom/images/my_company.img ]];then
        cp -rf devices/common/my_company_empty.img build/portrom/images/my_company.img
    fi
elif [[ $is_ab_device == false ]];then
    rm -rf build/portrom/images/my_company.img
    rm -rf build/portrom/images/my_preload.img
fi

pack_timestamp=$(date +"%m%d%H%M")
if [[ $pack_method == "stock" ]];then
    rm -rf out/target/product/${base_product_device}/
    mkdir -p out/target/product/${base_product_device}/IMAGES
    mkdir -p out/target/product/${base_product_device}/META
    for part in SYSTEM SYSTEM_EXT PRODUCT VENDOR MY_MANIFEST; do
        mkdir -p out/target/product/${base_product_device}/$part
    done
    mv -f build/portrom/images/*.img out/target/product/${base_product_device}/IMAGES/
    if [[ -d build/baserom/firmware-update ]];then
        bootimg=$(find build/baserom/ -name "boot.img")
        cp -rf $bootimg out/target/product/${base_product_device}/IMAGES/
    else
        if [[ -f build/baserom/images/init_boot-kernelsu.img ]];then
            mv build/baserom/images/init_boot-kernelsu.img build/baserom/images/init_boot.img
        fi
        mv -f build/baserom/images/*.img out/target/product/${base_product_device}/IMAGES/
    fi

    if [[ -d devices/${base_product_device} ]];then

        ksu_bootimg_file=$(find devices/$base_product_device/ -type f -name "*boot_ksu.img")
        dtbo_file=$(find devices/$base_product_device/ -type f -name "*dtbo_ksu.img")
        if [ -n "$ksu_bootimg_file" ];then
            mv -f "$ksu_bootimg_file" out/target/product/${base_product_device}/IMAGES/boot.img
            [[ -n "$dtbo_file" && -f "$dtbo_file" ]] && mv -f "$dtbo_file" out/target/product/${base_product_device}/IMAGES/dtbo.img
        else
            spoof_bootimg out/target/product/${base_product_device}/IMAGES/boot.img
        fi
    fi
    rm -rf out/target/product/${base_product_device}/META/ab_partitions.txt
    rm -rf out/target/product/${base_product_device}/META/update_engine_config.txt
    rm -rf out/target/product/${base_product_device}/target-file.zip
    _map_targets=()
    super_list_info=""
    while IFS= read -r part; do
        [[ -f "${part}" ]] || continue
        partname=$(basename "$part" .img)
        echo "$partname" >> "out/target/product/${base_product_device}/META/ab_partitions.txt"
        if echo "$super_list" | grep -q -w "$partname"; then
            super_list_info+="$partname "
            _map_targets+=("$partname")
        fi
    done < <(printf '%s\n' out/target/product/${base_product_device}/IMAGES/*.img | LC_ALL=C sort)
    if [[ ${#_map_targets[@]} -gt 0 ]]; then
        _map_jobs="$(port_cpu_count)"
        (( _map_jobs > 32 )) && _map_jobs=32
        PORT_OTA_IMAGES_DIR="${work_dir}/out/target/product/${base_product_device}/IMAGES"
        export PORT_OTA_IMAGES_DIR
        blue "并行生成分区 .map 文件 (${_map_jobs} 线程)" "Generating partition .map files in parallel (${_map_jobs} job(s))"
        port_run_jobs "${_map_jobs}" "${work_dir}/build/logs/map-gen" _port::generate_map_file "${_map_targets[@]}" || {
            error "生成 .map 文件失败" "Failed to generate partition .map files"
            exit 1
        }
    fi
    rm -rf out/target/product/${base_product_device}/META/dynamic_partitions_info.txt
    let groupSize=superSize-1048576
    {
        echo "super_partition_size=$superSize"
        echo "super_partition_groups=qti_dynamic_partitions"
        echo "super_qti_dynamic_partitions_group_size=$groupSize"
        echo "super_qti_dynamic_partitions_partition_list=$super_list_info"
        echo "virtual_ab=true"
        echo "virtual_ab_compression=true"
    } >> out/target/product/${base_product_device}/META/dynamic_partitions_info.txt

    {
        echo "default_system_dev_certificate=key/testkey"
        echo "recovery_api_version=3"
        echo "fstab_version=2"
        echo "ab_update=true"
     } >> out/target/product/${base_product_device}/META/misc_info.txt
    
    {
        echo "PAYLOAD_MAJOR_VERSION=2"
        echo "PAYLOAD_MINOR_VERSION=8"
    } >> out/target/product/${base_product_device}/META/update_engine_config.txt

    if [[ "$is_ab_device" == false ]];then
        sed -i "/ab_update=true/d" out/target/product/${base_product_device}/META/misc_info.txt
        {
            echo "blockimgdiff_versions=3,4"
            echo "use_dynamic_partitions=true"
            echo "dynamic_partition_list=$super_list_info"
            echo "super_partition_groups=qti_dynamic_partitions"
            echo "super_qti_dynamic_partitions_group_size=$superSize"
            echo "super_qti_dynamic_partitions_partition_list=$super_list_info"
            echo "board_uses_vendorimage=true"
            echo "cache_size=402653184"

        } >> out/target/product/${base_product_device}/META/misc_info.txt
        mkdir -p out/target/product/${base_product_device}/OTA/bin
        for part in MY_PRODUCT MY_BIGBALL MY_CARRIER MY_ENGINEERING MY_HEYTAP MY_MANIFEST MY_REGION MY_STOCK;do
            mkdir -p out/target/product/${base_product_device}/$part
        done

        if [[ -f devices/${base_product_device}/OTA/bin/updater ]];then
            cp -rf devices/${base_product_device}/OTA/bin/updater out/target/product/${base_product_device}/OTA/bin
        else
            cp -rf devices/common/non-ab/OTA/updater out/target/product/${base_product_device}/OTA/bin
        fi
        if [[ -d build/baserom/firmware-update ]];then
            cp -rf build/baserom/firmware-update out/target/product/${base_product_device}/
        elif find build/baserom/ -type f \( -name "*.elf" -o -name "*.mdn" -o -name "*.bin" \) | grep -q .; then
            mkdir -p "out/target/product/${base_product_device}/firmware-update"
            for firmware in $(find build/baserom/ -type f \( -name "*.elf" -o -name "*.mdn" -o -name "*.bin" \));do
                mv -fv -- "${firmware}" "out/target/product/${base_product_device}/firmware-update/"
            done
            bootimg=$(find build/baserom/ -name "boot.img" -print -quit)
            dtboimg=$(find build/baserom/images -name "dtbo.img" -print -quit)
            vbmetaimg=$(find build/baserom/ -name "vbmeta.img" -print -quit)
            vmbeta_systemimg=$(find build/baserom/ -name "vbmeta_system.img" -print -quit)
            [[ -n "$bootimg" && -f "$bootimg" ]] && cp -rf -- "$bootimg" "out/target/product/${base_product_device}/IMAGES/"
            [[ -n "$dtboimg" && -f "$dtboimg" ]] && cp -rf -- "$dtboimg" "out/target/product/${base_product_device}/firmware-update"
            [[ -n "$vbmetaimg" && -f "$vbmetaimg" ]] && cp -rf -- "$vbmetaimg" "out/target/product/${base_product_device}/firmware-update"
            [[ -n "$vmbeta_systemimg" && -f "$vmbeta_systemimg" ]] && cp -rf -- "$vmbeta_systemimg" "out/target/product/${base_product_device}/firmware-update"
        fi

        if [[ -d build/baserom/storage-fw ]];then
            cp -rf build/baserom/storage-fw out/target/product/${base_product_device}/
            cp -rf build/baserom/ffu_tool out/target/product/${base_product_device}/storage-fw
        else
            cp -rf build/baserom/ffu_tool out/target/product/${base_product_device}/
	fi

        export OUT=$(pwd)/out/target/product/${base_product_device}/
        if [[ -f devices/${base_product_device}/releasetools.py ]];then
            cp -rf devices/${base_product_device}/releasetools.py out/target/product/${base_product_device}/META/
        else
            cp -rf devices/common/releasetools.py out/target/product/${base_product_device}/META/
        fi

        mkdir -p out/target/product/${base_product_device}/RECOVERY/RAMDISK/etc/
        if [[ -f devices/${base_product_device}/recovery.fstab ]];then
            cp -rf devices/${base_product_device}/recovery.fstab out/target/product/${base_product_device}/RECOVERY/RAMDISK/etc/
        else
            cp -rf devices/common/recovery.fstab out/target/product/${base_product_device}/RECOVERY/RAMDISK/etc/
        fi
    fi
    prop_dirs=(system product system_ext vendor my_manifest)
    prop_targets=(SYSTEM PRODUCT SYSTEM_EXT VENDOR MY_MANIFEST)

    for prop_index in "${!prop_dirs[@]}"; do
        dir="${prop_dirs[$prop_index]}"
        prop_file=$(find "build/portrom/images/$dir" -type f -name "build.prop" -not -path "*/system_dlkm/*" -not -path "*/odm_dlkm/*" -print -quit)
        
        if [ -n "$prop_file" ]; then
            target_dir="out/target/product/${base_product_device}/${prop_targets[$prop_index]}"
            if [ ! -d "$target_dir" ]; then
                mkdir -p "$target_dir"
            fi
            cp "$prop_file" "$target_dir/"
        fi
    done
    target_folder=${rom_version#*_}
    if [[ "${PORT_LOW_DISK:-false}" == true ]]; then
        # All target-files metadata and images have been staged. OTA generation
        # needs them, not the uncompressed patch/extraction working trees.
        rm -rf -- tmp build/baserom build/portrom
        mkdir -p tmp
        df -h .
    fi
    mkdir -p "${work_dir}/out/${target_folder}"
    _ota_target_files="${work_dir}/out/target/product/${base_product_device}"
    _ota_out_zip="${work_dir}/out/${base_product_device}-ota_full-${port_rom_version}-user-${port_android_version}.0.zip"
    _ota_built=false
    if [[ "${is_ab_device}" == true ]]; then
        case "${ota_engine}" in
            rust)
                _port::build_ab_ota_rust "${_ota_target_files}" "${_ota_out_zip}" || {
                    error "Rust payload-gen 不可用或生成 OTA 失败" "Rust payload-gen unavailable or OTA generation failed"
                    exit 1
                }
                _ota_built=true
                ;;
            delta)
                _port::build_ab_ota_delta "${_ota_target_files}" "${_ota_out_zip}" || {
                    error "delta_generator 不可用或生成 OTA 失败" "delta_generator unavailable or OTA generation failed"
                    exit 1
                }
                _ota_built=true
                ;;
            auto)
                if type _port::build_ab_ota_rust >/dev/null 2>&1 && _port::build_ab_ota_rust "${_ota_target_files}" "${_ota_out_zip}"; then
                    _ota_built=true
                elif _port::build_ab_ota_delta "${_ota_target_files}" "${_ota_out_zip}"; then
                    _ota_built=true
                else
                    yellow "快速 A/B OTA 路径不可用，回退到 ota_from_target_files" "Fast A/B OTA path unavailable; falling back to ota_from_target_files"
                fi
                ;;
            stock) ;;
        esac
    fi
    if [[ "${_ota_built}" != true ]]; then
        pushd otatools || exit 1
        export PATH=$(pwd)/bin/:$PATH
        ./bin/ota_from_target_files --partial= --force_minor_version 9 "${_ota_target_files}/" "${_ota_out_zip}" || exit 1
        popd
    fi
    ziphash="$(port_sha256_file "out/${base_product_device}-ota_full-${port_rom_version}-user-${port_android_version}.0.zip")" || exit 1
    ziphash="${ziphash:0:10}"
    mv -f out/${base_product_device}-ota_full-${port_rom_version}-user-${port_android_version}.0.zip out/$target_folder/ota_full-${rom_version}-${port_product_model}-${pack_timestamp}-$regionmark-${portrom_version_security_patch}-${ziphash}.zip
	blue "打包完成： out/$target_folder/ota_full-${rom_version}-${port_product_model}-${pack_timestamp}-$regionmark-${portrom_version_security_patch}-${ziphash}.zip"
else
   if [[ $is_ab_device == true ]]; then
        # 打包 super.img
        blue "打包V-A/B机型 super.img" "Packing super.img for V-AB device"
        lpargs="-F --virtual-ab --output build/portrom/images/super.img --metadata-size 65536 --super-name super --metadata-slots 3 --device super:$superSize --group=qti_dynamic_partitions_a:$superSize --group=qti_dynamic_partitions_b:$superSize"

        for pname in ${super_list};do
            if [ -f "build/portrom/images/${pname}.img" ];then
                subsize="$(port_file_size_bytes "build/portrom/images/${pname}.img")" || exit 1
                green "Super 子分区 [$pname] 大小 [$subsize]" "Super sub-partition [$pname] size: [$subsize]"
                args="--partition ${pname}_a:none:${subsize}:qti_dynamic_partitions_a --image ${pname}_a=build/portrom/images/${pname}.img --partition ${pname}_b:none:0:qti_dynamic_partitions_b"
                lpargs="$lpargs $args"
                unset subsize
                unset args
            fi
        done
    else
        blue "打包A-only super.img" "Packing super.img for A-only device"
        lpargs="-F --output build/portrom/images/super.img --metadata-size 65536 --super-name super --metadata-slots 2 --block-size 4096 --device super:$superSize --group=qti_dynamic_partitions:$superSize"
        for pname in ${super_list};do
            if [ -f "build/portrom/images/${pname}.img" ];then
                subsize="$(port_file_size_bytes "build/portrom/images/${pname}.img")" || exit 1
                green "Super 子分区 [$pname] 大小 [$subsize]" "Super sub-partition [$pname] size: [$subsize]"
                args="--partition ${pname}:none:${subsize}:qti_dynamic_partitions --image ${pname}=build/portrom/images/${pname}.img"
                lpargs="$lpargs $args"
                unset subsize
                unset args
            fi
        done
    fi
    lpmake $lpargs
    if [ -f "build/portrom/images/super.img" ];then
        green "成功打包 super.img" "Pakcing super.img done."
    else
        error "无法打包 super.img"  "Unable to pack super.img."
        exit 1
    fi
    if [[ "${PORT_LOW_DISK:-false}" == true ]]; then
        for pname in ${super_list};do
            rm -f "build/portrom/images/${pname}.img"
        done
        df -h .
    fi

    blue "正在压缩 super.img" "Comprising super.img"
    zstd -T0 build/portrom/images/super.img -o build/portrom/super.zst || exit 1
    if [[ "${PORT_LOW_DISK:-false}" == true ]]; then
        rm -f build/portrom/images/super.img
        rm -rf tmp
        df -h .
    fi

    blue "正在生成刷机脚本" "Generating flashing script"

    mkdir -p out/${os_type}_${rom_version}/META-INF/com/google/android/   
    mkdir -p out/${os_type}_${rom_version}/firmware-update
    mkdir -p out/${os_type}_${rom_version}/bin/windows/
    cp -rf bin/flash/platform-tools-windows/* out/${os_type}_${rom_version}/bin/windows/
    cp -rf bin/flash/windows_flash_script.bat out/${os_type}_${rom_version}/
    cp -rf bin/flash/mac_linux_flash_script.sh out/${os_type}_${rom_version}/
    cp -rf bin/flash/zstd out/${os_type}_${rom_version}/META-INF/
    mv -f build/portrom/*.zst out/${os_type}_${rom_version}/
    if [[ -f devices/${base_product_device}/update-binary ]];then
        cp -rf devices/${base_product_device}/update-binary out/${os_type}_${rom_version}/META-INF/com/google/android/
    else
        cp -rf bin/flash/update-binary out/${os_type}_${rom_version}/META-INF/com/google/android/
    fi
    if [[ $is_ab_device = "false" ]];then
        mv -f build/baserom/firmware-update/*.img out/${os_type}_${rom_version}/firmware-update
        for fwimg in $(ls out/${os_type}_${rom_version}/firmware-update |cut -d "." -f 1 |grep -vE "super|cust|preloader");do
            if [[ $fwimg == *"xbl"* ]] || [[ $fwimg == *"dtbo"* ]] ;then
                # Warning: If wrong xbl img has been flashed, it will cause phone hard brick, so we just skip it with fastboot mode.
                continue

            elif [[ ${fwimg} == "BTFM" ]];then
                part="bluetooth"
            elif [[ ${fwimg} == "cdt_engineering" ]];then
                part="engineering_cdt"
            elif [[ ${fwimg} == "dspso" ]];then
                part="dsp"
            elif [[ ${fwimg} == "keymaster64" ]];then
                part="keymaster"
            elif [[ ${fwimg} == "qupv3fw" ]];then
                part="qupfw"
            elif [[ ${fwimg} == "static_nvbk" ]];then
                part="static_nvbk"
            else
                part=${fwimg}                
            fi

            sed -i "/REM firmware/a \\\bin\\\windows\\\fastboot.exe flash "${part}" firmware-update\/"${fwimg}".img || exit /B 1" out/${os_type}_${rom_version}/windows_flash_script.bat
            sed -i "/# firmware/a fastboot flash "${part}" firmware-update\/"${fwimg}".img || exit 1" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        done
        sed -i "/_b/d" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "s/_a//g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "/_b/d" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        sed -i "s/_a//g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        sed -i '/^REM SET_ACTION_SLOT_A_BEGIN/,/^REM SET_ACTION_SLOT_A_END/d' out/${os_type}_${rom_version}/windows_flash_script.bat
        sed -i '/# SET_ACTION_SLOT_A_BEGIN/,/# SET_ACTION_SLOT_A_END/d' out/${os_type}_${rom_version}/mac_linux_flash_script.sh
    else
        mv -f build/baserom/images/*.img out/${os_type}_${rom_version}/firmware-update
        for fwimg in $(ls out/${os_type}_${rom_version}/firmware-update |cut -d "." -f 1 |grep -vE "super|cust|preloader");do
            if [[ $fwimg == *"xbl"* ]] || [[ $fwimg == *"dtbo"* ]] || [[ $fwimg == *"reserve"* ]] || [[ $fwimg == "boot" ]] || [[ $fwimg == boot_* ]] || [[ $fwimg == *_dlkm ]];then
                rm -rf out/${os_type}_${rom_version}/firmware-update/*reserve*
                # Skip xbl/dtbo/boot (handled explicitly) and dynamic *_dlkm (inside super.img).
                continue
            elif [[ $fwimg == "mdm_oem_stanvbk" ]] || [[ $fwimg == "spunvm" ]] ;then
                sed -i "/REM firmware/a \\\bin\\\windows\\\fastboot.exe flash "${fwimg}" firmware-update\/"${fwimg}".img || exit /B 1" out/${os_type}_${rom_version}/windows_flash_script.bat
                sed -i "/\# firmware/a fastboot flash "${fwimg}" firmware-update\/"${fwimg}".img || exit 1" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
            elif [ "$(echo ${fwimg} |grep vbmeta)" != "" ];then
                sed -i "/REM firmware/a \\\bin\\\windows\\\fastboot.exe --disable-verity --disable-verification flash "${fwimg}"_b firmware-update\/"${fwimg}".img || exit /B 1" out/${os_type}_${rom_version}/windows_flash_script.bat
                sed -i "/REM firmware/a \\\bin\\\windows\\\fastboot.exe --disable-verity --disable-verification flash "${fwimg}"_a firmware-update\/"${fwimg}".img || exit /B 1" out/${os_type}_${rom_version}/windows_flash_script.bat
                sed -i "/\# firmware/a fastboot --disable-verity --disable-verification flash "${fwimg}"_b firmware-update\/"${fwimg}".img || exit 1" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
                sed -i "/\# firmware/a fastboot --disable-verity --disable-verification flash "${fwimg}"_a firmware-update\/"${fwimg}".img || exit 1" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
            else
                sed -i "/REM firmware/a \\\bin\\\windows\\\fastboot.exe flash "${fwimg}"_b firmware-update\/"${fwimg}".img || exit /B 1" out/${os_type}_${rom_version}/windows_flash_script.bat
                sed -i "/REM firmware/a \\\bin\\\windows\\\fastboot.exe flash "${fwimg}"_a firmware-update\/"${fwimg}".img || exit /B 1" out/${os_type}_${rom_version}/windows_flash_script.bat
                sed -i "/\# firmware/a fastboot flash "${fwimg}"_b firmware-update\/"${fwimg}".img || exit 1" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
                sed -i "/\# firmware/a fastboot flash "${fwimg}"_a firmware-update\/"${fwimg}".img || exit 1" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
            fi
        done
    fi

    sed -i "s/device_code/${base_product_device}/g" out/${os_type}_${rom_version}/windows_flash_script.bat
    sed -i "s/REGIONMARK/${regionmark}/g" out/${os_type}_${rom_version}/windows_flash_script.bat
    sed -i "s/device_code/${base_product_device}/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
    sed -i "s/REGIONMARK/${regionmark}/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
    sed -i "s/device_code/${base_product_device}/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
    sed -i "s/REGIONMARK/${regionmark}/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
    sed -i "s/portversion/${port_rom_version}/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
    sed -i "s/baseversion/${base_rom_version}/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
    sed -i "s/andVersion/${port_android_version}/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
    sed -i "s/PROJECT_CODE/${base_device_code}/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary

    unix2dos out/${os_type}_${rom_version}/windows_flash_script.bat

    #disable vbmeta
    _out_vbmeta_imgs=()
    while IFS= read -r -d '' img; do
        blue "vbmeta验证禁用： $img" "Disable vbmeta verify: $img"
        _out_vbmeta_imgs+=("${img}")
    done < <(find "out/${os_type}_${rom_version}/" -type f -name "vbmeta*.img" -print0)
    if [[ ${#_out_vbmeta_imgs[@]} -gt 0 ]]; then
        run_rom_ops patch-vbmeta "${_out_vbmeta_imgs[@]}"
        _out_vbmeta_rc=$?
        if [[ ${_out_vbmeta_rc} -eq 127 ]]; then
            for img in "${_out_vbmeta_imgs[@]}"; do
                python3 bin/patch-vbmeta.py "${img}"
            done
        elif [[ ${_out_vbmeta_rc} -ne 0 ]]; then
            exit "${_out_vbmeta_rc}"
        fi
    fi

    ksu_bootimg_file=$(find devices/$base_product_device/ -type f -name "*boot_ksu.img")
    nonksu_bootimg_file=$(find devices/$base_product_device/ -type f -name "*boot_noksu.img")
    custom_bootimg_file=$(find devices/$base_product_device/ -type f -name "*boot_custom.img")

    if [[ -f $nonksu_bootimg_file ]];then
        nonksubootimg=$(basename "$nonksu_bootimg_file")
        mv -f "$nonksu_bootimg_file" out/${os_type}_${rom_version}/
        [[ -f "devices/$base_product_device/dtbo_noksu.img" ]] && \
            mv -f "devices/$base_product_device/dtbo_noksu.img" "out/${os_type}_${rom_version}/firmware-update/dtbo_noksu.img"
        sed -i "s/boot_official.img/$nonksubootimg/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "s/boot_official.img/$nonksubootimg/g" out/${os_type}_${rom_version}/windows_flash_script.bat
        sed -i "s/boot_official.img/$nonksubootimg/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        sed -i "s/dtbo.img/dtbo_noksu.img/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "s/dtbo.img/dtbo_noksu.img/g" out/${os_type}_${rom_version}/windows_flash_script.bat
        sed -i "s/dtbo.img/dtbo_noksu.img/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        sed -i '/^REM OFFICAL_BOOT_START/,/^REM OFFICAL_BOOT_END/d' out/${os_type}_${rom_version}/windows_flash_script.bat
    else
        bootimg=$(find build/baserom/ out/${os_type}_${rom_version} -name "boot.img")
        mv -f $bootimg out/${os_type}_${rom_version}/boot_official.img
    fi

    if [[ -f "$ksu_bootimg_file" ]];then
        ksubootimg=$(basename "$ksu_bootimg_file")
        mv -f "$ksu_bootimg_file" out/${os_type}_${rom_version}/
        [[ -f "devices/$base_product_device/dtbo_ksu.img" ]] && \
            mv -f "devices/$base_product_device/dtbo_ksu.img" "out/${os_type}_${rom_version}/firmware-update/dtbo_ksu.img"
        sed -i "s/boot_tv.img/$ksubootimg/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "s/boot_tv.img/$ksubootimg/g" out/${os_type}_${rom_version}/windows_flash_script.bat
        sed -i "s/boot_tv.img/$ksubootimg/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        sed -i "s/dtbo_tv.img/dtbo_ksu.img/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "s/dtbo_tv.img/dtbo_ksu.img/g" out/${os_type}_${rom_version}/windows_flash_script.bat
        sed -i "s/dtbo_tv.img/dtbo_ksu.img/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        sed -i '/^REM OFFICAL_BOOT_START/,/^REM OFFICAL_BOOT_END/d' out/${os_type}_${rom_version}/windows_flash_script.bat
        
    elif [[ -f "$custom_bootimg_file" ]];then
        custombootimg=$(basename "$custom_bootimg_file")
        mv -f "$custom_bootimg_file" out/${os_type}_${rom_version}/
        [[ -f "devices/$base_product_device/dtbo_custom.img" ]] && \
            mv -f "devices/$base_product_device/dtbo_custom.img" "out/${os_type}_${rom_version}/firmware-update/dtbo_custom.img"
        sed -i "s/boot_tv.img/$custombootimg/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "s/boot_tv.img/$custombootimg/g" out/${os_type}_${rom_version}/windows_flash_script.bat
        sed -i "s/boot_tv.img/$custombootimg/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        sed -i "s/dtbo_tv.img/dtbo_custom.img/g" out/${os_type}_${rom_version}/META-INF/com/google/android/update-binary
        sed -i "s/dtbo_tv.img/dtbo_custom.img/g" out/${os_type}_${rom_version}/windows_flash_script.bat
        sed -i "s/dtbo_tv.img/dtbo_custom.img/g" out/${os_type}_${rom_version}/mac_linux_flash_script.sh
        
    fi

    if [[ "${PORT_LOW_DISK:-false}" == true ]]; then
        # Firmware and boot images have now been staged into the package.
        rm -rf -- build/baserom
    fi
    find out/${os_type}_${rom_version} |xargs touch
    pushd out/${os_type}_${rom_version}/ >/dev/null || exit
    # Images are already zstd-compressed. Avoid compressing them a second time.
    zip -0 -r "${os_type}_${rom_version}.zip" ./* || exit 1
    mv ${os_type}_${rom_version}.zip ../
    popd >/dev/null || exit
    pack_timestamp=$(date +"%m%d%H%M")
    hash="$(port_sha256_file "out/${os_type}_${rom_version}.zip")" || exit 1
    hash="${hash:0:10}"
    if [[ $pack_type == "EROFS" ]] && [[ -f out/${os_type}_${rom_version}/$ksubootimg ]];then
        pack_type="ROOT_"${pack_type}
    fi
    mv out/${os_type}_${rom_version}.zip out/${os_type}_${rom_version}_${hash}_${port_product_model}_${pack_timestamp}_${pack_type}.zip
    green "移植完毕" "Porting completed"    
    green "输出包路径：" "Output: "
    green "$(pwd)/out/${os_type}_${rom_version}_${hash}_${port_product_model}_${pack_timestamp}_${pack_type}.zip"
fi
