import socket
import threading
import json
import zlib
import uuid
import traceback
from protocol import PacketBuffer
from mappings import BLOCK_NEW_TO_OLD, BLOCK_OLD_TO_NEW, DEFAULT_BLOCK_OLD

# ========== 内部固定常量，不允许外部配置 ==========
PROTOCOL_152 = 61
PROTOCOL_MODERN = 776
STATE_HANDSHAKE = 0
STATE_LOGIN = 2
STATE_PLAY = 3

# ========== 加载JSON配置 ==========
with open("config.json", "r", encoding="utf-8") as f:
    cfg = json.load(f)

PROXY_HOST = cfg["proxy_host"]
PROXY_PORT = cfg["proxy_port"]
SERVER_HOST = cfg["server_host"]
SERVER_PORT = cfg["server_port"]
SERVER_MOTD = cfg["server_motd"]
MAX_PLAYERS = cfg["max_players"]

# ========== 工具函数 ==========
def json_chat_to_legacy(text_json: str) -> str:
    """新版 JSON 聊天转 1.5.2 § 格式纯文本"""
    try:
        data = json.loads(text_json)
        return _parse_chat_component(data)
    except:
        return text_json

def _parse_chat_component(comp) -> str:
    result = ""
    if isinstance(comp, str):
        return comp
    if isinstance(comp, list):
        for item in comp:
            result += _parse_chat_component(item)
        return result

    color_map = {
        "black": "0", "dark_blue": "1", "dark_green": "2", "dark_aqua": "3",
        "dark_red": "4", "dark_purple": "5", "gold": "6", "gray": "7",
        "dark_gray": "8", "blue": "9", "green": "a", "aqua": "b",
        "red": "c", "light_purple": "d", "yellow": "e", "white": "f"
    }

    if "text" in comp:
        result += comp["text"]
    elif "translate" in comp:
        result += comp.get("translate", "")

    color_code = "§f"
    if "color" in comp:
        c = comp["color"]
        if c in color_map:
            color_code = "§" + color_map[c]

    format_codes = ""
    if comp.get("bold"): format_codes += "§l"
    if comp.get("italic"): format_codes += "§o"
    if comp.get("underlined"): format_codes += "§n"
    if comp.get("strikethrough"): format_codes += "§m"
    if comp.get("obfuscated"): format_codes += "§k"

    result = color_code + format_codes + result
    if "extra" in comp:
        result += _parse_chat_component(comp["extra"])
    return result

# ========== 现代端读写（修复版） ==========
def send_packet_modern(sock: socket.socket, payload: bytes, compression_threshold: int = -1):
    if compression_threshold <= 0:
        buf = PacketBuffer()
        buf.write_varint(len(payload))
        buf.write(payload)
        sock.sendall(buf.getvalue())
    else:
        uncompressed_len = len(payload)
        body_buf = PacketBuffer()
        if uncompressed_len >= compression_threshold:
            compressed = zlib.compress(payload)
            body_buf.write_varint(uncompressed_len)
            body_buf.write(compressed)
        else:
            body_buf.write_varint(0)
            body_buf.write(payload)
        
        body = body_buf.getvalue()
        outer_buf = PacketBuffer()
        outer_buf.write_varint(len(body))
        outer_buf.write(body)
        sock.sendall(outer_buf.getvalue())

def read_packet_modern(sock: socket.socket, compression_threshold: int = -1) -> tuple[int, PacketBuffer]:
    # 读取外层总长度
    length_buf = PacketBuffer()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("服务端连接已关闭")
        length_buf.write(b)
        if (ord(b) & 0x80) == 0:
            break
    length_buf.buf.seek(0)
    total_length = length_buf.read_varint()

    # 精确读取完整包体
    data = b""
    while len(data) < total_length:
        chunk = sock.recv(total_length - len(data))
        if not chunk:
            raise ConnectionError("服务端连接中断")
        data += chunk

    buf = PacketBuffer(data)

    if compression_threshold <= 0:
        # 未压缩模式
        packet_id = buf.read_varint()
        return packet_id, buf
    else:
        # 压缩模式：先读未压缩长度
        uncompressed_len = buf.read_varint()
        if uncompressed_len == 0:
            # 未压缩小包
            packet_id = buf.read_varint()
            return packet_id, buf
        else:
            # 读取剩余全部压缩数据并解压
            remaining = buf.buf.read()
            uncompressed_data = zlib.decompress(remaining)
            result_buf = PacketBuffer(uncompressed_data)
            packet_id = result_buf.read_varint()
            return packet_id, result_buf

# ========== 旧端读写 ==========
def read_packet_152(sock: socket.socket) -> tuple[int, PacketBuffer]:
    id_byte = sock.recv(1)
    if not id_byte:
        raise ConnectionError("客户端连接已关闭")
    packet_id = ord(id_byte)
    buf = PacketBuffer()

    if packet_id == 0x02:  # Handshake
        proto = sock.recv(1)
        buf.write(proto)
        len_bytes = sock.recv(2)
        buf.write(len_bytes)
        name_len = int.from_bytes(len_bytes, "big")
        buf.write(sock.recv(name_len * 2))
        host_len_bytes = sock.recv(2)
        buf.write(host_len_bytes)
        host_len = int.from_bytes(host_len_bytes, "big")
        buf.write(sock.recv(host_len * 2))
        buf.write(sock.recv(4))
    elif packet_id == 0x03:  # Chat
        len_bytes = sock.recv(2)
        buf.write(len_bytes)
        msg_len = int.from_bytes(len_bytes, "big")
        buf.write(sock.recv(msg_len * 2))
    elif packet_id == 0xFF:  # Disconnect
        len_bytes = sock.recv(2)
        buf.write(len_bytes)
        reason_len = int.from_bytes(len_bytes, "big")
        buf.write(sock.recv(reason_len * 2))
    else:
        known_lengths = {
            0x00: 0, 0x01: 4, 0x04: 4, 0x06: 12, 0x08: 10,
            0x09: 0, 0x0A: 1, 0x0B: 33, 0x0C: 9, 0x0D: 41,
            0x0E: 11, 0x0F: 11, 0x12: 10, 0x13: 5, 0x65: 1,
            0x6A: 3, 0x6B: 3, 0x6C: 2, 0xFE: 0
        }
        if packet_id in known_lengths:
            remaining = known_lengths[packet_id]
            while remaining > 0:
                chunk = sock.recv(remaining)
                if not chunk:
                    raise ConnectionError("连接中断")
                buf.write(chunk)
                remaining -= len(chunk)
        else:
            sock.settimeout(0.05)
            try:
                while True:
                    chunk = sock.recv(128)
                    if not chunk: break
                    buf.write(chunk)
            except socket.timeout:
                pass
            finally:
                sock.settimeout(None)

    return packet_id, buf

# ========== 核心连接处理器 ==========
class ProxyConnection:
    def __init__(self, client_sock: socket.socket, addr):
        self.client_sock = client_sock
        self.addr = addr
        self.server_sock = None
        self.client_state = STATE_HANDSHAKE
        self.server_state = STATE_HANDSHAKE
        self.username = ""
        self.compression_threshold = -1
        self.running = True

    def start(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.settimeout(5)
            self.server_sock.connect((SERVER_HOST, SERVER_PORT))
            self.server_sock.settimeout(None)
            print(f"[连接] 客户端 {self.addr} 已接入，后端连接建立")

            t_client = threading.Thread(target=self._client_to_server, daemon=True)
            t_server = threading.Thread(target=self._server_to_client, daemon=True)
            t_client.start()
            t_server.start()
            t_client.join()
            t_server.join()
        except Exception as e:
            print(f"[致命错误] 初始化失败: {e}")
            traceback.print_exc()
        finally:
            self.running = False
            self.client_sock.close()
            if self.server_sock:
                self.server_sock.close()
            print(f"[断开] 客户端 {self.addr} 连接关闭\n")

    # ---- 客户端 -> 服务端 ----
    def _client_to_server(self):
        try:
            while self.running:
                packet_id, buf = read_packet_152(self.client_sock)
                print(f"[C->S] 包ID: 0x{packet_id:02X} | 状态: {self.client_state}")
                buf.buf.seek(0)  # 旧端包体不含包ID，需要复位指针
                self._handle_client_packet(packet_id, buf)
        except ConnectionError as e:
            print(f"[C->S] 连接断开: {e}")
        except Exception as e:
            print(f"[C->S] 异常: {e}")
            traceback.print_exc()
        finally:
            self.running = False

    def _handle_client_packet(self, packet_id: int, buf: PacketBuffer):
        # ===== 服务器列表 Ping =====
        if packet_id == 0xFE:
            # 1.5.2 老式 Ping 响应格式：§1\0协议号\0版本\0MOTD\0在线\0最大
            response = f"§1\x00{PROTOCOL_152}\x001.5.2\x00{SERVER_MOTD}\x000\x00{MAX_PLAYERS}"
            out = PacketBuffer()
            out.write_byte(0xFF)
            out.write_string_152(response)
            self.client_sock.sendall(out.getvalue())
            print(f"[Ping] 响应服务器列表查询，MOTD: {SERVER_MOTD}")
            self.running = False
            return

        # ===== 握手包 =====
        if self.client_state == STATE_HANDSHAKE and packet_id == 0x02:
            proto_ver = buf.read_byte()
            username = buf.read_string_152()
            server_host = buf.read_string_152()
            server_port = buf.read_int()

            self.username = username
            print(f"[握手] 协议版本: {proto_ver} | 用户名: {username}")

            handshake = PacketBuffer()
            handshake.write_varint(0x00)
            handshake.write_varint(PROTOCOL_MODERN)
            handshake.write_string(server_host)
            handshake.write_ushort(server_port)
            handshake.write_varint(2)
            send_packet_modern(self.server_sock, handshake.getvalue(), self.compression_threshold)

            player_uuid = str(uuid.uuid3(uuid.NAMESPACE_URL, f"OfflinePlayer:{username}"))
            login = PacketBuffer()
            login.write_varint(0x00)
            login.write_string(username)
            login.write_uuid(player_uuid)
            send_packet_modern(self.server_sock, login.getvalue(), self.compression_threshold)
            print(f"[登录] 已发送 Login Hello: {username}")

            self.client_state = STATE_LOGIN
            self.server_state = STATE_LOGIN
            return

        # ===== 聊天消息 =====
        if self.client_state == STATE_PLAY and packet_id == 0x03:
            message = buf.read_string_152()
            print(f"[聊天] {self.username}: {message}")

            chat = PacketBuffer()
            chat.write_varint(0x05)
            chat.write_string(message)
            chat.write_varint(0)
            send_packet_modern(self.server_sock, chat.getvalue(), self.compression_threshold)
            return

    # ---- 服务端 -> 客户端 ----
    def _server_to_client(self):
        try:
            while self.running:
                packet_id, buf = read_packet_modern(self.server_sock, self.compression_threshold)
                print(f"[S->C] 包ID: 0x{packet_id:02X} | 状态: {self.server_state}")
                # 注意：现代包已跳过包ID，缓冲区指针已在字段开头，禁止 seek(0)
                self._handle_server_packet(packet_id, buf)
        except ConnectionError as e:
            print(f"[S->C] 连接断开: {e}")
        except Exception as e:
            print(f"[S->C] 异常: {e}")
            traceback.print_exc()
        finally:
            self.running = False

    def _handle_server_packet(self, packet_id: int, buf: PacketBuffer):
        # ===== 登录阶段：断开 =====
        if self.server_state == STATE_LOGIN and packet_id == 0x00:
            reason = buf.read_string()
            print(f"[服务端拒绝] {reason}")
            out = PacketBuffer()
            out.write_byte(0xFF)
            out.write_string_152(json_chat_to_legacy(reason))
            self.client_sock.sendall(out.getvalue())
            self.running = False
            return

        # ===== 登录阶段：设置压缩 =====
        if self.server_state == STATE_LOGIN and packet_id == 0x03:
            self.compression_threshold = buf.read_varint()
            print(f"[压缩] 启用压缩，阈值: {self.compression_threshold}")
            return

        # ===== 登录阶段：登录成功 =====
        if self.server_state == STATE_LOGIN and packet_id == 0x02:
            uuid_ret = buf.read_uuid()
            name_ret = buf.read_string()
            print(f"[登录成功] UUID: {uuid_ret} | 用户名: {name_ret}")

            out = PacketBuffer()
            out.write_byte(0x01)
            out.write_int(12345)
            out.write_string_152("default")
            out.write_byte(0)
            out.write_byte(0)
            out.write_byte(0)
            out.write_byte(MAX_PLAYERS)
            out.write_byte(0)
            self.client_sock.sendall(out.getvalue())

            self.client_state = STATE_PLAY
            self.server_state = STATE_PLAY
            self._send_basic_join_game()
            return

        # ===== 游戏阶段：聊天消息 =====
        if self.server_state == STATE_PLAY and packet_id == 0x30:
            try:
                msg_json = buf.read_string()
                legacy_text = json_chat_to_legacy(msg_json)
                out = PacketBuffer()
                out.write_byte(0x03)
                out.write_string_152(legacy_text[:100])
                self.client_sock.sendall(out.getvalue())
                return
            except:
                pass

    def _send_basic_join_game(self):
        # 出生点
        out = PacketBuffer()
        out.write_byte(0x06)
        out.write_int(0)
        out.write_int(64)
        out.write_int(0)
        self.client_sock.sendall(out.getvalue())

        # 血量饥饿
        out = PacketBuffer()
        out.write_byte(0x08)
        out.write_short(20)
        out.write_short(20)
        out.write_float(5.0)
        self.client_sock.sendall(out.getvalue())

        # 玩家位置
        out = PacketBuffer()
        out.write_byte(0x0D)
        out.write_double(0.0)
        out.write_double(65.0)
        out.write_double(0.0)
        out.write_double(0.0)
        out.write_float(0.0)
        out.write_float(0.0)
        out.write_bool(True)
        self.client_sock.sendall(out.getvalue())

        print("[初始化] 已发送基础游戏状态包")

# ========== 主入口 ==========
def main():
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except:
        print("[提示] 系统不支持双栈，仅监听 IPv6")
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(5)

    print("=" * 50)
    print("1.5.2 <-> Paper 26.2 协议转换代理")
    print(f"代理监听: [{PROXY_HOST}]:{PROXY_PORT} (IPv4/IPv6 双栈)")
    print(f"后端服务: {SERVER_HOST}:{SERVER_PORT}")
    print(f"协议版本: 1.5.2(v{PROTOCOL_152}) <-> 26.2(v{PROTOCOL_MODERN})")
    print("=" * 50)
    print("等待客户端连接...\n")

    while True:
        cli, addr = server.accept()
        conn = ProxyConnection(cli, addr)
        threading.Thread(target=conn.start, daemon=True).start()

if __name__ == "__main__":
    main()
