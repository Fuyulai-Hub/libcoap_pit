#!/bin/bash

# 设置日志输出
set -e  # 出错立即退出
apt-get update
apt-get install -y sudo 
# 1. 移除无效的 Mono 仓库（避免 apt update 失败）
echo "Removing invalid Mono repository..."
sudo rm -f /etc/apt/sources.list.d/mono-official-stable.list || true
# 更新包列表并安装依赖
sudo apt-get update || { echo "Failed to update package list"; exit 1; }
sudo apt-get upgrade -y || { echo "Failed to upgrade packages"; exit 1; }

sudo apt-get install -y \
    unzip \
    git build-essential \
    llvm llvm-dev clang \
    autoconf automake pkg-config libtool libtool-bin \
    gnutls-dev libgnutls28-dev lcov wget || { echo "Failed to install dependencies"; exit 1; }

# 创建工作目录并进入
cd /root/ || { echo "Failed to change directory to /root"; exit 1; }

REPO_URLS=(
    "https://gitee.com/fyulai/pcguard-cov.git"
    "https://github.com/Fuyulai-Hub/libcoap_pit.git"
)

for url in "${REPO_URLS[@]}"; do
    dir_name=$(basename "$url" .git)  # 自动提取目录名（如 repo1）
    if [ -d "$dir_name" ]; then
        echo "skipping clone: $dir_name"
    else
        echo "start clone: $url"
        git clone "$url"
    fi
done
# 进入目录并解压
cd pcguard-cov || { echo "Failed to enter pcguard-cov directory"; exit 1; }
unzip -o pcguard-cov.zip || { echo "Failed to unzip pcguard-cov.zip"; exit 1; }

# 编译 pcguard-cov
make || { echo "Failed to make pcguard-cov"; exit 1; }

# 进入 llvm_mode 目录并编译
cd llvm_mode || { echo "Failed to enter llvm_mode directory"; exit 1; }
AFL_TRACE_PC=1 make || { echo "Failed to make llvm_mode"; exit 1; }

# 回到根目录并克隆 libcoap
cd /root/libcoap_pit || { echo "Failed to return to root directory"; exit 1; }
# 配置 libcoap 的编译环境
cd libcoap || { echo "Failed to enter libcoap directory"; exit 1; }
export CC=/root/pcguard-cov/afl-clang-fast
export CXX=/root/pcguard-cov/afl-clang-fast++
export CFLAGS="-Wall -O2 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fsanitize-coverage=trace-pc-guard"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-fsanitize=address,undefined"
export AFL_USE_ASAN=1 ASAN_OPTIONS=detect_leaks=0

# 执行构建步骤
./autogen.sh || { echo "Failed to run autogen.sh"; exit 1; }
./configure --disable-doxygen --disable-manpages --enable-tests --disable-documentation --enable-examples --disable-shared --disable-tests || { echo "Failed to configure libcoap"; exit 1; }
make -j || { echo "Failed to make libcoap"; exit 1; }

echo "All operations completed successfully!"
