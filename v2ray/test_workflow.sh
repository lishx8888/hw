#!/bin/bash

# 测试脚本，用于验证工作流中的主要功能
echo "开始测试节点更新工作流..."
echo "当前时间: $(date)"

# 测试Python环境
echo "\n检查Python版本:"
python --version

# 检查依赖安装
echo "\n检查必要的Python包:"
pip list | grep -E 'requests|beautifulsoup4|pyyaml'

# 测试scrape.py脚本
echo "\n测试节点抓取脚本:"
python scrape.py --test || echo "注意: 测试模式下可能会失败，这是正常的"

# 检查v2ray.txt文件是否存在
echo "\n检查v2ray.txt文件:"
if [ -f "v2ray.txt" ]; then
  echo "v2ray.txt存在，包含 $(cat v2ray.txt | wc -l) 个节点"
else
  echo "警告: v2ray.txt不存在或为空"
fi

# 测试to_clash.py脚本（如果v2ray.txt存在）
if [ -f "v2ray.txt" ] && [ -s "v2ray.txt" ]; then
  echo "\n测试Clash转换脚本:"
  python to_clash.py --test || echo "注意: 测试模式下可能会失败，这是正常的"
  
  # 检查clash配置文件
  echo "\n检查Clash配置文件:"
  if [ -f "clash_config.yaml" ]; then
    echo "clash_config.yaml存在"
    # 显示配置文件的前几行
    echo "配置文件预览:"
    head -n 10 clash_config.yaml
  else
    echo "警告: clash_config.yaml不存在"
  fi
else
  echo "\n跳过Clash转换测试: v2ray.txt不存在或为空"
fi

echo "\n测试完成!"