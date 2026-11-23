#!/bin/bash

clear
cd "$(dirname "$0")" || exit 1
if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
	echo
	echo "1. 保留数据刷入"
	echo
	echo "2. 双清刷入"
	echo
	read -r -p "请选择(默认选择1,回车执行): " input
elif [[ "$LANG" =~ ^zh_.*\.UTF-8$ ]]; then
	echo
	echo "1. 保留數據刷入"
	echo
	echo "2. 雙清刷入"
	echo
	read -r -p "請選擇(默認選擇1,回車執行): " input
else
	echo
	echo "1. Preserve user data during flashing"
	echo
	echo "2. Wiping data"
	echo
	read -r -p "Please select (1 is selected by default, enter to execute): " input
fi
input="$(printf '%s' "${input:-1}" | tr -d '\r')"
if [ "$input" != "1" ] && [ "$input" != "2" ]; then
	echo "Invalid selection: $input"
	exit 1
fi

os_name="$(uname -s 2>/dev/null || echo Unknown)"
if [ "$os_name" != "Darwin" ] && command -v apt-get >/dev/null 2>&1; then
	printf '\033]0;mac_linux_flash_script\007'
fi

install_missing_tool() {
	tool="$1"
	pkg_brew="$2"
	pkg_apt="$3"
	if command -v "$tool" >/dev/null 2>&1; then
		return 0
	fi
	if [ "$os_name" = "Darwin" ]; then
		if command -v brew >/dev/null 2>&1; then
			brew install "$pkg_brew" || return 1
		else
			echo "Missing $tool and Homebrew is not installed." >&2
			return 1
		fi
	elif command -v apt-get >/dev/null 2>&1; then
		sudo apt-get update && sudo apt-get install -y "$pkg_apt" || return 1
	else
		echo "Missing required tool '$tool'. Please install '$pkg_apt' using your package manager." >&2
		return 1
	fi
}

install_missing_tool fastboot android-platform-tools fastboot || exit 1
install_missing_tool zstd zstd zstd || exit 1

fastboot_path="$(command -v fastboot)"
if [ -n "$fastboot_path" ]; then
	export ANDROID_PRODUCT_OUT
	ANDROID_PRODUCT_OUT="$(dirname "$fastboot_path")"
fi

if [ -f "super.zst" ]; then
	if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
		echo "正在解压super镜像,耐心等待"
	elif [[ "$LANG" =~ ^zh_.*\.UTF-8$ ]]; then
		echo "正在解壓super鏡像，耐心等待"
	else
		echo "Extracting the super image, wait patiently"
	fi
	rm -f super.img.tmp
	if ! zstd -d super.zst -o super.img.tmp; then
		rm -f super.img.tmp
		echo "Conversion failed." >&2
		exit 1
	fi
	mv -f super.img.tmp super.img || exit 1
	rm -f super.zst
fi

if [ ! -f "super.img" ]; then
	echo "Required super.img is missing." >&2
	exit 1
fi

if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
	echo "机型验证中...请确保您的设备代号为device_code，并已经进入bootloader或fastbootd模式。"
elif [[ "$LANG" =~ ^zh_.*\.UTF-8$ ]]; then
	echo "機型驗證中...請確保您的設備代號為device_code，並已進入bootloader或fastbootd模式。"
else
	echo "Validating device...please boot your device into bootloader or fastbootd and make sure your device code is device_code"
fi

fb() {
	fastboot "${FB_ARGS[@]}" "$@"
}

FB_ARGS=("$@")

get_fb_var() {
	var_name="$1"
	raw_out="$(fb getvar "$var_name" 2>&1 || true)"
	printf '%s\n' "$raw_out" | tr -d '\r' | sed -n -E "s/^(\\(bootloader\\)[[:space:]]*)?${var_name}:[[:space:]]*//p" | head -n 1 | awk '{print $1}'
}

userspace="$(get_fb_var is-userspace)"
if [ "$userspace" = "yes" ]; then
	echo "Detected fastbootd mode, rebooting into bootloader..."
	fb reboot bootloader || exit 1
	tries=0
	while [ "$tries" -lt 15 ]; do
		sleep 2
		userspace="$(get_fb_var is-userspace)"
		if [ "$userspace" = "no" ]; then
			break
		fi
		tries=$((tries + 1))
	done
	if [ "$userspace" != "no" ]; then
		echo "Timed out waiting for bootloader." >&2
		exit 1
	fi
fi

device_product="$(get_fb_var product)"
if [ "$device_product" != "device_code" ]; then
	if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
		echo "机型device_code校验失败 (检测到: ${device_product:-empty})，检查包是否匹配" >&2
	elif [[ "$LANG" =~ ^zh_.*\.UTF-8$ ]]; then
		echo "機型device_code校驗失敗 (檢測到: ${device_product:-empty})，檢查包是否匹配" >&2
	else
		echo "Mismatching image and device: got '${device_product:-empty}', expected 'device_code'" >&2
	fi
	exit 1
fi

kernel=2
if [ -f "boot_ksu.img" ]; then
	if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
		echo
		echo "1. 刷入KSU内核"
		echo "2. 刷入官方内核"
		read -r -p "请选择(默认选择1,回车执行): " kernel
	else
		echo
		echo "1. Flashing KernelSU boot.img"
		echo "2. Flashing Official boot.img"
		read -r -p "Please select (1 is selected by default, enter to execute): " kernel
	fi
	kernel="$(printf '%s' "${kernel:-1}" | tr -d '\r')"
fi

flash_boot="boot_official.img"
flash_dtbo="firmware-update/dtbo.img"
if [ "$kernel" = "1" ] && [ -f "boot_ksu.img" ]; then
	flash_boot="boot_ksu.img"
	if [ -f "firmware-update/dtbo_ksu.img" ]; then
		flash_dtbo="firmware-update/dtbo_ksu.img"
	fi
fi

if [ ! -f "$flash_boot" ] || [ ! -f "$flash_dtbo" ]; then
	echo "Required boot ($flash_boot) or dtbo ($flash_dtbo) image is missing." >&2
	exit 1
fi

set -e

echo "Flashing $flash_boot and $flash_dtbo..."
fb flash boot_a "$flash_boot"
fb flash boot_b "$flash_boot"
fb flash dtbo_a "$flash_dtbo"
fb flash dtbo_b "$flash_dtbo"

# firmware

fb erase super
fb flash super super.img

if [ "$input" = "2" ]; then
	if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
		echo "正在双清系统,耐心等待"
	elif [[ "$LANG" =~ ^zh_.*\.UTF-8$ ]]; then
		echo "正在雙清系統，耐心等待"
	else
		echo "Wiping data, please wait patiently"
	fi
	fb erase userdata
	fb erase metadata
fi
# SET_ACTION_SLOT_A_BEGIN
if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
	echo "设置活动分区为 'a'。可能需要一些时间。请勿手动重新启动或拔掉数据线，否则可能导致设备变砖。"
elif [[ "$LANG" =~ ^zh_.*\.UTF-8$ ]]; then
	echo "開始將活動分區設置為 'a'。這可能需要一些時間。請勿手動重新啟動或拔掉數據線，否則可能導致設備無法響應。"
else
	echo "Starting the process to set the active slot to 'a.' This may take some time. Please refrain from manually restarting or unplugging the data cable, as doing so could result in the device becoming unresponsive."
fi
fb set_active a
# SET_ACTION_SLOT_A_END

fb reboot

if [ "$LANG" = "C.UTF-8" ] || [ "$LANG" = "zh_CN.UTF-8" ]; then
	echo "刷机完成,若手机长时间未重启请手动重启"
elif [[ "$LANG" =~ ^zh_.*\.UTF-8$ ]]; then
	echo "刷機完成，若手機長時間未重啓請手動重啓"
else
	echo "Flash completed. If the phone does not restart for an extended period, please manually restart."
fi
exit 0
