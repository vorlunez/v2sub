from v2sub import utils

V2RAY_CONFIG_FILE = "/tmp/config-{}.json"


def _get_settings_vmess(addr: str, port: int, id_: str) -> dict:
    return {
        "vnext": [
            {
                "address": addr,
                "port": port,
                "users": [{"id": id_}]
            }
        ]
    }


def _get_settings_vless(node: dict) -> dict:
    user = {
        "id": node["id"],
        "encryption": node.get("encryption", "none"),
    }
    if node.get("flow"):
        user["flow"] = node["flow"]
    return {
        "vnext": [
            {
                "address": node["add"],
                "port": int(node["port"]),
                "users": [user],
            }
        ]
    }


def _get_settings_ss(addr: str, port: int, method: str, password: str) -> dict:
    return {
        "servers": [
            {
                "address": addr,
                "port": port,
                "method": method,
                "password": password
            }
        ]
    }


def _get_stream_settings(node: dict) -> dict:
    network = node.get("network", "tcp")
    security = node.get("security", "none")
    stream_settings = {
        "network": network,
        "security": security,
    }

    if security == "tls":
        tls_settings = {}
        if node.get("sni"):
            tls_settings["serverName"] = node["sni"]
        if node.get("fp"):
            tls_settings["fingerprint"] = node["fp"]
        if node.get("alpn"):
            tls_settings["alpn"] = node["alpn"].split(",")
        if node.get("allowInsecure"):
            tls_settings["allowInsecure"] = (
                node["allowInsecure"].lower() in ("1", "true")
            )
        stream_settings["tlsSettings"] = tls_settings
    elif security == "reality":
        reality_settings = {}
        reality_fields = {
            "sni": "serverName",
            "fp": "fingerprint",
            "pbk": "publicKey",
            "sid": "shortId",
            "spx": "spiderX",
        }
        for source, target in reality_fields.items():
            if node.get(source):
                reality_settings[target] = node[source]
        stream_settings["realitySettings"] = reality_settings

    if network == "ws":
        ws_settings = {}
        if node.get("path"):
            ws_settings["path"] = node["path"]
        if node.get("host"):
            ws_settings["headers"] = {"Host": node["host"]}
        stream_settings["wsSettings"] = ws_settings
    elif network == "grpc":
        grpc_settings = {}
        if node.get("serviceName"):
            grpc_settings["serviceName"] = node["serviceName"]
        if node.get("authority"):
            grpc_settings["authority"] = node["authority"]
        stream_settings["grpcSettings"] = grpc_settings
    elif network == "http":
        http_settings = {}
        if node.get("path"):
            http_settings["path"] = node["path"]
        if node.get("host"):
            http_settings["host"] = node["host"].split(",")
        stream_settings["httpSettings"] = http_settings
    elif network == "kcp":
        kcp_settings = {}
        if node.get("headerType"):
            kcp_settings["header"] = {"type": node["headerType"]}
        if node.get("seed"):
            kcp_settings["seed"] = node["seed"]
        stream_settings["kcpSettings"] = kcp_settings
    elif network == "tcp" and node.get("headerType"):
        stream_settings["tcpSettings"] = {
            "header": {"type": node["headerType"]}
        }

    return stream_settings


def _get_config(node: dict, client_port=1080) -> dict:
    match node['protocol']:
        case 'vmess':
            settings = _get_settings_vmess(node['add'], int(node['port']), node['id'])
        case 'vless':
            settings = _get_settings_vless(node)
        case 'shadowsocks':
            settings = _get_settings_ss(node['add'], int(node['port']),
                                        node['method'], node['password'])
        case _:
            raise ValueError("Unsupported protocol: %s" % node['protocol'])
    outbound = {
        "protocol": node['protocol'],
        "settings": settings,
    }
    if node['protocol'] == 'vless':
        outbound["streamSettings"] = _get_stream_settings(node)
    return {
        "inbounds": [
            {
                "port": client_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "sniffing": {
                    "enable": True,
                    "destOverride": ["http", "tls"]
                },
                "settings": {
                    "auth": "noauth",
                    "udp": True
                }
            }
        ],
        "outbounds": [
            outbound,
            {
                "protocol": "freedom",
                "tag": "direct",
                "settings": {}
            }
        ],
        "routing": {
            "domainStrategy": "IPOnDemand",
            "rules": [
                {
                    "type": "field",
                    "domain": ["geosite:cn"],
                    "ip": ["geoip:private", "geoip:cn"],
                    "outboundTag": "direct"
                }
            ]
        }
    }


def update_config(node: dict, client_port: int):
    v2ray_config = _get_config(node, client_port=client_port)
    utils.write_to_json(v2ray_config, V2RAY_CONFIG_FILE.format(client_port))
