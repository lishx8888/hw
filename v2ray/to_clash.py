import base64
import json
import logging
import re
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def decode_v2ray_link(link):
    """解码v2ray链接，提取节点信息"""
    try:
        # 提取base64部分
        if link.startswith(('vmess://', 'vless://', 'trojan://', 'ss://')):
            protocol = link.split('://')[0]
            encoded_data = link.split('://')[1]
            
            # 对于ss协议，需要特殊处理
            if protocol == 'ss':
                # ss链接格式: ss://base64(user:pass)@host:port#name
                # 或者 ss://base64(加密方式:password)@host:port#name
                # 尝试直接解码
                try:
                    # 确保padding正确
                    padding = len(encoded_data) % 4
                    if padding:
                        encoded_data += '=' * (4 - padding)
                    
                    decoded = base64.b64decode(encoded_data).decode('utf-8')
                    # 解析ss链接的组成部分
                    match = re.match(r'([^@]+)@([^:]+):(\d+)(#(.*))?', decoded)
                    if match:
                        method_pass = match.group(1)
                        server = match.group(2)
                        port = int(match.group(3))
                        name = match.group(5) or f"{protocol}_{server}:{port}"
                        
                        # 分离加密方式和密码
                        if ':' in method_pass:
                            method, password = method_pass.split(':', 1)
                        else:
                            method = 'aes-256-cfb'  # 默认加密方式
                            password = method_pass
                            
                        return {
                            'protocol': protocol,
                            'name': name,
                            'server': server,
                            'port': port,
                            'method': method,
                            'password': password
                        }
                except Exception as e:
                    logging.warning(f"ss链接解码失败: {str(e)}")
            
            # 对于其他协议，先base64解码
            try:
                # 确保padding正确
                padding = len(encoded_data) % 4
                if padding:
                    encoded_data += '=' * (4 - padding)
                
                decoded = base64.b64decode(encoded_data).decode('utf-8')
                
                # vmess是json格式
                if protocol == 'vmess':
                    data = json.loads(decoded)
                    data['protocol'] = protocol
                    return data
                
                # vless和trojan格式类似URL
                elif protocol in ['vless', 'trojan']:
                    # 解析URL格式
                    parsed = urlparse(f"http://{decoded}")
                    user_info = parsed.username or ''
                    server = parsed.hostname
                    port = parsed.port
                    fragment = parsed.fragment  # 节点名称
                    query_params = parse_qs(parsed.query)
                    
                    # 提取必要信息
                    result = {
                        'protocol': protocol,
                        'name': fragment or f"{protocol}_{server}:{port}",
                        'server': server,
                        'port': port
                    }
                    
                    # 添加协议特定信息
                    if protocol == 'vless':
                        result['id'] = user_info
                        if 'encryption' in query_params:
                            result['encryption'] = query_params['encryption'][0]
                        if 'security' in query_params:
                            result['security'] = query_params['security'][0]
                        if 'sni' in query_params:
                            result['sni'] = query_params['sni'][0]
                        if 'path' in query_params:
                            result['path'] = query_params['path'][0]
                        if 'host' in query_params:
                            result['host'] = query_params['host'][0]
                    elif protocol == 'trojan':
                        result['password'] = user_info
                        if 'sni' in query_params:
                            result['sni'] = query_params['sni'][0]
                        if 'path' in query_params:
                            result['path'] = query_params['path'][0]
                        if 'host' in query_params:
                            result['host'] = query_params['host'][0]
                    
                    return result
            except Exception as e:
                logging.warning(f"{protocol}链接解码失败: {str(e)}")
    except Exception as e:
        logging.error(f"解码v2ray链接时出错: {str(e)}")
    return None

def v2ray_to_clash(node_info):
    """将v2ray节点信息转换为clash配置"""
    try:
        protocol = node_info.get('protocol')
        name = node_info.get('name', f"{protocol}_node")
        
        # 处理名称中的特殊字符
        name = re.sub(r'[\\/:*?\"<>|]', '_', name)
        
        if protocol == 'vmess':
            # vmess转clash
            clash_node = {
                "name": name,
                "type": "vmess",
                "server": node_info.get('add', ''),
                "port": node_info.get('port', 443),
                "uuid": node_info.get('id', ''),
                "alterId": node_info.get('aid', 0),
                "cipher": node_info.get('scy', "auto"),
                "tls": node_info.get('tls', "") == "tls",
                "skip-cert-verify": True
            }
            
            # 添加网络配置
            if node_info.get('net', "") == "ws":
                clash_node["network"] = "ws"
                ws_opts = {}
                if "path" in node_info:
                    ws_opts["path"] = node_info["path"]
                if "host" in node_info:
                    ws_opts["headers"] = {"Host": node_info["host"]}
                clash_node["ws-opts"] = ws_opts
            elif node_info.get('net', "") == "h2":
                clash_node["network"] = "h2"
                h2_opts = {}
                if "path" in node_info:
                    h2_opts["path"] = node_info["path"]
                if "host" in node_info:
                    h2_opts["host"] = [node_info["host"]]
                clash_node["h2-opts"] = h2_opts
            
            # 添加SNI
            if "sni" in node_info:
                clash_node["servername"] = node_info["sni"]
                
            return clash_node
        
        elif protocol == 'vless':
            # vless转clash
            clash_node = {
                "name": name,
                "type": "vless",
                "server": node_info.get('server', ''),
                "port": node_info.get('port', 443),
                "uuid": node_info.get('id', ''),
                "encryption": node_info.get('encryption', "none"),
                "tls": True if node_info.get('security') == "tls" else False,
                "skip-cert-verify": True
            }
            
            # 添加网络配置
            if "path" in node_info:
                clash_node["network"] = "ws"
                clash_node["ws-opts"] = {
                    "path": node_info["path"]
                }
                if "host" in node_info:
                    clash_node["ws-opts"]["headers"] = {"Host": node_info["host"]}
            
            # 添加SNI
            if "sni" in node_info:
                clash_node["servername"] = node_info["sni"]
            
            return clash_node
        
        elif protocol == 'trojan':
            # trojan转clash
            clash_node = {
                "name": name,
                "type": "trojan",
                "server": node_info.get('server', ''),
                "port": node_info.get('port', 443),
                "password": node_info.get('password', ''),
                "skip-cert-verify": True
            }
            
            # 添加SNI
            if "sni" in node_info:
                clash_node["sni"] = node_info["sni"]
            
            # 添加websocket配置
            if "path" in node_info:
                clash_node["network"] = "ws"
                clash_node["ws-opts"] = {
                    "path": node_info["path"]
                }
                if "host" in node_info:
                    clash_node["ws-opts"]["headers"] = {"Host": node_info["host"]}
            
            return clash_node
        
        elif protocol == 'ss':
            # ss转clash
            clash_node = {
                "name": name,
                "type": "ss",
                "server": node_info.get('server', ''),
                "port": node_info.get('port', 8388),
                "cipher": node_info.get('method', "aes-256-cfb"),
                "password": node_info.get('password', '')
            }
            return clash_node
    
    except Exception as e:
        logging.error(f"转换节点 {node_info.get('name', 'unknown')} 到clash时出错: {str(e)}")
    
    return None

def create_clash_config(nodes, output_file="clash_config.yaml"):
    """创建完整的clash配置文件"""
    try:
        import yaml
        
        # 基础clash配置
        clash_config = {
            "mixed-port": 7890,
            "allow-lan": True,
            "bind-address": "*",
            "mode": "Rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "proxies": [],
            "proxy-groups": [
                {
                    "name": "🔰 节点选择",
                    "type": "select",
                    "proxies": []
                },
                {
                    "name": "🎯 全球直连",
                    "type": "select",
                    "proxies": ["DIRECT"]
                },
                {
                    "name": "🌏 国外媒体",
                    "type": "select",
                    "proxies": ["🔰 节点选择", "DIRECT"]
                },
                {
                    "name": "📢 电报消息",
                    "type": "select",
                    "proxies": ["🔰 节点选择", "DIRECT"]
                },
                {
                    "name": "🇭🇰 香港节点",
                    "type": "select",
                    "proxies": ["DIRECT"]
                },
                {
                    "name": "🇯🇵 日本节点",
                    "type": "select",
                    "proxies": ["DIRECT"]
                },
                {
                    "name": "🇰🇷 韩国节点",
                    "type": "select",
                    "proxies": ["DIRECT"]
                },
                {
                    "name": "🇺🇸 美国节点",
                    "type": "select",
                    "proxies": ["DIRECT"]
                },
                {
                    "name": "🇬🇧 英国节点",
                    "type": "select",
                    "proxies": ["DIRECT"]
                },
                {
                    "name": "🎮 游戏加速",
                    "type": "select",
                    "proxies": ["🔰 节点选择", "DIRECT"]
                },
                {
                    "name": "🛑 广告拦截",
                    "type": "select",
                    "proxies": ["REJECT"]
                }
            ],
            "rules": [
                "RULE-SET,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/RuleSet/AdBlock/LocalAdBlock.list,🛑 广告拦截",
                "DOMAIN,clash.razord.top,🔰 节点选择",
                "DOMAIN-SUFFIX,google.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,googleapis.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,gmail.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,youtube.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,facebook.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,twitter.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,instagram.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,telegram.org,📢 电报消息",
                "DOMAIN-SUFFIX,github.com,🌏 国外媒体",
                "DOMAIN-SUFFIX,githubusercontent.com,🌏 国外媒体",
                "GEOIP,CN,🎯 全球直连",
                "MATCH,🔰 节点选择"
            ]
        }
        
        # 添加节点到配置中
        node_names = []
        for node in nodes:
            if node:
                clash_config["proxies"].append(node)
                node_names.append(node["name"])
        
        # 更新节点选择组
        if node_names:
            clash_config["proxy-groups"][0]["proxies"] = node_names + ["DIRECT"]
        
        # 生成配置内容
        # 手动构建YAML头部，以确保正确的格式
        header = f"""
# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# 节点数量: {len(node_names)}
"""
        
        # 使用PyYAML生成YAML内容
        yaml_content = yaml.dump(clash_config, allow_unicode=True, sort_keys=False)
        
        # 合并头部和YAML内容
        full_content = header + yaml_content
        
        # 保存到文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_content)
        
        logging.info(f"成功生成clash配置文件: {output_file}, 包含 {len(node_names)} 个节点")
        return output_file
        
    except ImportError:
        logging.error("PyYAML未安装，请先运行: pip install pyyaml")
        # 创建一个简化版本，不使用PyYAML
        create_simple_clash_config(nodes, output_file)
    except Exception as e:
        logging.error(f"创建clash配置时出错: {str(e)}")

def create_simple_clash_config(nodes, output_file="clash_config.yaml"):
    """创建简化版的clash配置文件（不依赖PyYAML）"""
    try:
        content = [
            f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# 节点数量: {len(nodes)}",
            "mixed-port: 7890",
            "allow-lan: true",
            "bind-address: '*'",
            "mode: Rule",
            "log-level: info",
            "external-controller: 127.0.0.1:9090",
            "proxies:"
        ]
        
        # 添加proxies
        for node in nodes:
            if not node:
                continue
            
            content.append(f"  - name: '{node['name']}'")
            content.append(f"    type: {node['type']}")
            content.append(f"    server: {node['server']}")
            content.append(f"    port: {node['port']}")
            
            # 添加协议特定配置
            if node['type'] == 'vmess':
                content.append(f"    uuid: {node['uuid']}")
                content.append(f"    alterId: {node['alterId']}")
                content.append(f"    cipher: {node['cipher']}")
                content.append(f"    tls: {str(node['tls']).lower()}")
                content.append(f"    skip-cert-verify: true")
                if 'network' in node:
                    content.append(f"    network: {node['network']}")
                    if node['network'] == 'ws' and 'ws-opts' in node:
                        content.append("    ws-opts:")
                        if 'path' in node['ws-opts']:
                            content.append(f"      path: '{node['ws-opts']['path']}'")
                        if 'headers' in node['ws-opts'] and 'Host' in node['ws-opts']['headers']:
                            content.append("      headers:")
                            content.append(f"        Host: '{node['ws-opts']['headers']['Host']}'")
            elif node['type'] == 'vless':
                content.append(f"    uuid: {node['uuid']}")
                content.append(f"    encryption: {node['encryption']}")
                content.append(f"    tls: {str(node['tls']).lower()}")
                content.append(f"    skip-cert-verify: true")
            elif node['type'] == 'trojan':
                content.append(f"    password: '{node['password']}'")
                content.append(f"    skip-cert-verify: true")
                if 'sni' in node:
                    content.append(f"    sni: '{node['sni']}'")
            elif node['type'] == 'ss':
                content.append(f"    cipher: {node['cipher']}")
                content.append(f"    password: '{node['password']}'")
        
        # 添加proxy-groups
        content.append("proxy-groups:")
        content.append("  - name: '🔰 节点选择'")
        content.append("    type: select")
        content.append("    proxies:")
        for node in nodes:
            if node:
                content.append(f"      - '{node['name']}'")
        content.append("      - DIRECT")
        
        # 添加基本规则
        content.append("rules:")
        content.append("  - DOMAIN-SUFFIX,google.com,🔰 节点选择")
        content.append("  - DOMAIN-SUFFIX,youtube.com,🔰 节点选择")
        content.append("  - DOMAIN-SUFFIX,facebook.com,🔰 节点选择")
        content.append("  - DOMAIN-SUFFIX,twitter.com,🔰 节点选择")
        content.append("  - DOMAIN-SUFFIX,github.com,🔰 节点选择")
        content.append("  - GEOIP,CN,DIRECT")
        content.append("  - MATCH,🔰 节点选择")
        
        # 保存到文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(content))
        
        logging.info(f"成功生成简化版clash配置文件: {output_file}, 包含 {len([n for n in nodes if n])} 个节点")
        return output_file
        
    except Exception as e:
        logging.error(f"创建简化版clash配置时出错: {str(e)}")

def convert_v2ray_to_clash(input_file="v2ray.txt", output_file="clash_config.yaml"):
    """将v2ray.txt文件转换为clash配置文件"""
    try:
        logging.info(f"开始转换: {input_file} -> {output_file}")
        
        # 读取v2ray.txt文件
        with open(input_file, 'r', encoding='utf-8') as f:
            encoded_data = f.read().strip()
        
        # 解码base64数据
        try:
            # 确保padding正确
            padding = len(encoded_data) % 4
            if padding:
                encoded_data += '=' * (4 - padding)
            
            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
        except Exception as e:
            logging.error(f"解码base64数据失败: {str(e)}")
            # 尝试直接读取文件内容（假设文件已经是解码后的纯文本）
            decoded_data = encoded_data
            logging.info("尝试直接处理文件内容")
        
        # 解析每一行作为一个v2ray链接
        lines = decoded_data.strip().split('\n')
        logging.info(f"读取到 {len(lines)} 行数据")
        
        # 转换每个节点
        clash_nodes = []
        processed_count = 0
        success_count = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            processed_count += 1
            # 解码v2ray链接
            v2ray_info = decode_v2ray_link(line)
            if v2ray_info:
                # 转换为clash格式
                clash_node = v2ray_to_clash(v2ray_info)
                if clash_node:
                    clash_nodes.append(clash_node)
                    success_count += 1
                else:
                    logging.warning(f"转换失败: {v2ray_info.get('name', line[:50])}")
            else:
                logging.warning(f"解码失败: {line[:50]}...")
        
        # 去重节点
        unique_nodes = []
        seen = set()
        for node in clash_nodes:
            node_key = f"{node['type']}:{node['server']}:{node['port']}"
            if node_key not in seen:
                seen.add(node_key)
                unique_nodes.append(node)
        
        logging.info(f"处理完成: 成功 {success_count}/{processed_count} 个节点，去重后剩余 {len(unique_nodes)} 个节点")
        
        # 创建clash配置文件
        if unique_nodes:
            create_clash_config(unique_nodes, output_file)
            return f"转换完成，成功生成 {output_file}，包含 {len(unique_nodes)} 个节点"
        else:
            return "没有成功转换任何节点"
            
    except FileNotFoundError:
        logging.error(f"文件不存在: {input_file}")
        return f"错误: 找不到文件 {input_file}"
    except Exception as e:
        logging.error(f"转换过程中出错: {str(e)}")
        return f"错误: {str(e)}"

if __name__ == "__main__":
    # 主程序入口
    logging.info("开始v2ray到clash的转换工具")
    
    # 尝试安装必要的依赖
    try:
        import yaml
    except ImportError:
        logging.warning("PyYAML未安装，将使用简化版输出")
    
    # 执行转换
    result = convert_v2ray_to_clash()
    print(result)
    logging.info("转换工具执行完毕")