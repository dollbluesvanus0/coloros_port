#!/bin/bash
# Shared I/O and packing helpers. Compatible with Bash 3.2 (macOS).

PORT_PERFORMANCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

port_tree_size_bytes() {
    local rc=127
    if type run_rom_ops >/dev/null 2>&1; then
        run_rom_ops tree-size "$1"
        rc=$?
        if (( rc != 127 )); then
            return "${rc}"
        fi
    fi
    python3 "${PORT_PERFORMANCE_ROOT}/bin/tree_size.py" "$1"
}

port_requires_browser() {
    local query
    for query in "$@"; do
        query="${query#"${query%%[![:space:]]*}"}"
        query="${query%"${query##*[![:space:]]}"}"
        case "${query}" in
            ''|http://*|https://*) ;;
            *) return 0 ;;
        esac
    done
    return 1
}

port_copy_image() {
    # Reflinks have independent contents; hard links would let later vbmeta
    # and boot patches corrupt the cached source image.
    if [[ -z "${PORT_COPY_MODE:-}" ]]; then
        local help
        help="$(cp --help 2>/dev/null)" || help=""
        if [[ "${help}" == *--reflink* ]]; then
            PORT_COPY_MODE=reflink
        else
            PORT_COPY_MODE=plain
        fi
    fi
    if [[ "${PORT_COPY_MODE}" == reflink ]]; then
        cp --reflink=auto --sparse=always -f -- "$1" "$2"
    else
        cp -f -- "$1" "$2"
    fi
}

port_copy_images() {
    local source_dir="$1" destination="$2" image count=0
    [[ -d "${source_dir}" ]] || return 1
    mkdir -p -- "${destination}" || return 1
    for image in "${source_dir}"/*.img; do
        [[ -f "${image}" ]] || continue
        port_copy_image "${image}" "${destination}/${image##*/}" || return 1
        count=$((count + 1))
    done
    (( count > 0 ))
}

port_cpu_count() {
    local cpus
    cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null)" || cpus=1
    [[ "${cpus}" =~ ^[1-9][0-9]*$ ]] || cpus=1
    printf '%s\n' "${cpus}"
}

port_pack_job_count() {
    local requested="${PORT_PACK_JOBS:-auto}" cpus="${1:-1}" jobs memory_kb
    if [[ "${requested}" != auto ]]; then
        if [[ ! "${requested}" =~ ^[1-9][0-9]?$ ]] || (( requested > 32 )); then
            printf 'PORT_PACK_JOBS must be auto or an integer from 1 to 32\n' >&2
            return 2
        fi
        printf '%s\n' "${requested}"
        return 0
    fi
    jobs=2
    (( cpus < jobs )) && jobs="${cpus}"
    if [[ -r /proc/meminfo ]]; then
        memory_kb="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)"
        if [[ "${memory_kb}" =~ ^[0-9]+$ ]] && (( memory_kb < 4 * 1024 * 1024 )); then
            jobs=1
        fi
    fi
    printf '%s\n' "${jobs}"
}

port_extract_job_count() {
    local requested="${PORT_EXTRACT_JOBS:-auto}" cpus="${1:-1}" jobs=4
    if [[ "${requested}" != auto ]]; then
        if [[ ! "${requested}" =~ ^[1-9][0-9]?$ ]] || (( requested > 32 )); then
            printf 'PORT_EXTRACT_JOBS must be auto or an integer from 1 to 32\n' >&2
            return 2
        fi
        printf '%s\n' "${requested}"
        return 0
    fi
    (( cpus < jobs )) && jobs="${cpus}"
    (( jobs < 1 )) && jobs=1
    printf '%s\n' "${jobs}"
}

port_patch_job_count() {
    local requested="${PORT_PATCH_JOBS:-auto}" cpus="${1:-1}" jobs=4 memory_kb
    if [[ "${requested}" != auto ]]; then
        if [[ ! "${requested}" =~ ^[1-9][0-9]?$ ]] || (( requested > 32 )); then
            printf 'PORT_PATCH_JOBS must be auto or an integer from 1 to 32\n' >&2
            return 2
        fi
        printf '%s\n' "${requested}"
        return 0
    fi
    (( cpus < jobs )) && jobs="${cpus}"
    if [[ -r /proc/meminfo ]]; then
        memory_kb="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)"
        if [[ "${memory_kb}" =~ ^[0-9]+$ ]] && (( memory_kb < 3 * 1024 * 1024 )) && (( jobs > 2 )); then
            jobs=2
        fi
    fi
    (( jobs < 1 )) && jobs=1
    printf '%s\n' "${jobs}"
}

port_wait_workers() {
    local pid
    # Keep the build lock until all writers finish, including on interruption.
    for pid in "${PORT_ACTIVE_PIDS[@]}"; do
        wait "${pid}" 2>/dev/null || true
    done
    PORT_ACTIVE_PIDS=()
}

port_run_jobs() {
    local limit="$1" log_dir="$2" worker="$3"
    shift 3
    [[ "${limit}" =~ ^[1-9][0-9]?$ ]] && (( limit <= 32 )) || return 2
    local next=0 failed=0 index part pid status
    local -a pending=("$@") pids=() names=() remaining_pids=() remaining_names=()
    mkdir -p -- "${log_dir}" || return 1
    PORT_ACTIVE_PIDS=()
    while (( next < ${#pending[@]} || ${#pids[@]} > 0 )); do
        while (( failed == 0 && next < ${#pending[@]} && ${#pids[@]} < limit )); do
            part="${pending[next]}"
            if [[ ! "${part}" =~ ^[A-Za-z0-9_]+$ ]]; then
                printf 'Invalid partition name: %s\n' "${part}" >&2
                failed=1
                break
            fi
            (
                # A worker must never run port.sh's parent EXIT cleanup and
                # release the build lock while other writers are still active.
                trap - EXIT
                "${worker}" "${part}"
            ) >"${log_dir}/${part}.log" 2>&1 &
            pids+=("$!")
            names+=("${part}")
            PORT_ACTIVE_PIDS=("${pids[@]}")
            next=$((next + 1))
        done
        remaining_pids=()
        remaining_names=()
        for index in "${!pids[@]}"; do
            pid="${pids[index]}"
            part="${names[index]}"
            if kill -0 "${pid}" 2>/dev/null; then
                remaining_pids+=("${pid}")
                remaining_names+=("${part}")
                continue
            fi
            status=0
            wait "${pid}" || status=$?
            cat -- "${log_dir}/${part}.log" || failed=1
            if (( status != 0 )); then
                printf 'Partition job %s failed (exit %s); log: %s/%s.log\n' \
                    "${part}" "${status}" "${log_dir}" "${part}" >&2
                failed=1
            fi
        done
        pids=("${remaining_pids[@]}")
        names=("${remaining_names[@]}")
        PORT_ACTIVE_PIDS=("${pids[@]}")
        # Refill the first free slot instead of waiting for an entire batch.
        if (( ${#pids[@]} > 0 )); then
            sleep 0.1
        elif (( failed != 0 )); then
            break
        fi
    done
    PORT_ACTIVE_PIDS=()
    return "${failed}"
}

port_pack_one_image() {
    local pname="$1" images="${work_dir}/build/portrom/images"
    local fs_config="${images}/config/${pname}_fs_config"
    local file_contexts="${images}/config/${pname}_file_contexts"
    local this_size started="${SECONDS}"
    if [[ ! -f "${fs_config}" || ! -f "${file_contexts}" ]]; then
        error "缺少 ${pname} 打包配置" "Missing ${pname} packing configuration"
        return 1
    fi
    blue "打包 [${pname}.img]" "Packing [${pname}.img] with [${pack_type}] filesystem"
    run_fs_and_context_patch "${images}/${pname}" "${fs_config}" "${file_contexts}" || return 1
    if [[ "${port_android_version:-0}" == 17 && "${pname}" == vendor ]]; then
        a17_patch_vendor_context_file "${file_contexts}" \
            "${work_dir}/build/diagnostics/a17-compat/originals/vendor-file-contexts" || return 1
    fi
    if [[ "${pack_type}" == EXT ]]; then
        this_size="$(port_tree_size_bytes "${images}/${pname}")" || return 1
        _port::pack_partition_ext4 "${pname}" "${images}/${pname}" \
            "${fs_config}" "${file_contexts}" "${images}/${pname}.img" "${this_size}" || return 1
    else
        # EROFS determines its size while building; a separate full tree walk
        # (and formerly one stat subprocess per file) contributes nothing.
        _port::pack_partition_erofs "${pname}" "${images}/${pname}" \
            "${fs_config}" "${file_contexts}" "${images}/${pname}.img" || return 1
    fi
    green "打包 [${pname}.img] 完成" "Packed [${pname}.img] in $((SECONDS - started))s"
}

port_pack_images() {
    local cpus jobs threads pname erofs_help seen=' '
    local -a partitions=()
    cpus="$(port_cpu_count)"
    jobs="$(port_pack_job_count "${cpus}")" || return $?
    threads=$((cpus / jobs))
    (( threads > 0 )) || threads=1
    export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-${threads}}"
    PORT_EROFS_WORKERS=""
    if [[ "${pack_type}" == EROFS ]]; then
        erofs_help="$(mkfs.erofs --help 2>&1)" || true
        # Older bundled ARM/macOS mkfs.erofs does not accept --workers.
        [[ "${erofs_help}" != *--workers=* ]] || PORT_EROFS_WORKERS="${threads}"
    fi
    for pname in "$@"; do
        [[ "${pname}" =~ ^[A-Za-z0-9_]+$ ]] || return 2
        [[ "${seen}" != *" ${pname} "* ]] || continue
        seen+="${pname} "
        [[ ! -d "${work_dir}/build/portrom/images/${pname}" ]] || partitions+=("${pname}")
    done
    blue "并行打包任务: ${jobs}" "Packing with ${jobs} job(s), ${threads} CPU thread(s) per job"
    port_run_jobs "${jobs}" "${work_dir}/build/logs/pack" port_pack_one_image "${partitions[@]}"
}
