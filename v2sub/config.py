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

def _get_config(node: dict, client_port=1080) -> dict:
    match node['protocol']:
        case 'vmess':
            settings = _get_settings_vmess(node['add'], int(node['port']), node['id'])
        case 'shadowsocks':
            settings = _get_settings_ss(node['add'], int(node['port']),
                                        node['method'], node['password'])
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
            {
                "protocol": node['protocol'],
                "settings": settings,
            },
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
