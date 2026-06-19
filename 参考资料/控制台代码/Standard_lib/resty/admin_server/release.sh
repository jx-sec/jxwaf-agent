#!/bin/sh
set -e

# 关键修改：切换到脚本所在目录
cd "$(dirname "$0")"

TARGET_DIR="../../../release_lib/resty/admin_server"

# 检查目标目录
if [ -d "$TARGET_DIR" ]; then
    rm -rf "$TARGET_DIR"/*
else
    mkdir -p "$TARGET_DIR"
fi

# 添加调试信息
echo "当前工作目录: $(pwd)"
echo "目标目录路径: $(realpath "$TARGET_DIR")"

for lua_file in *.lua; do
    if [ -f "$lua_file" ]; then
        echo "正在编译: $lua_file"
        filename=$(basename -- "$lua_file")
        filename="${filename%.*}"

        # 检查luajit路径是否存在
        if [ ! -f "/opt/jxwaf_admin_server/luajit/bin/luajit" ]; then
            echo "错误：luajit路径不存在！"
            exit 1
        fi

        /opt/jxwaf_admin_server/luajit/bin/luajit -b "$lua_file" "${filename}.luac"
        mv -v "${filename}.luac" "$TARGET_DIR/${filename}.lua"
    fi
done

echo "编译完成，生成文件："
ls -l "$TARGET_DIR"
