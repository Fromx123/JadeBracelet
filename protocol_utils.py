import struct
from io import BytesIO

class PacketBuffer:
    """Minecraft 数据包读写缓冲区"""
    def __init__(self, data: bytes = b""):
        self.buf = BytesIO(data)

    def read(self, n: int) -> bytes:
        return self.buf.read(n)

    def write(self, data: bytes):
        self.buf.write(data)

    def getvalue(self) -> bytes:
        return self.buf.getvalue()

    # ===== VarInt / VarLong =====
    def read_varint(self) -> int:
        value = 0
        position = 0
        while True:
            byte = self.read(1)
            if not byte:
                raise EOFError("VarInt 读取失败：数据不足")
            b = ord(byte)
            value |= (b & 0x7F) << position
            if (b & 0x80) == 0:
                break
            position += 7
            if position >= 32:
                raise ValueError("VarInt 过大")
        return value

    def write_varint(self, value: int):
        while True:
            if (value & ~0x7F) == 0:
                self.write(bytes([value]))
                return
            self.write(bytes([(value & 0x7F) | 0x80]))
            value >>= 7

    # ===== 基础数据类型 =====
    def read_byte(self) -> int:
        return ord(self.read(1))

    def write_byte(self, value: int):
        self.write(bytes([value & 0xFF]))

    def read_short(self) -> int:
        return struct.unpack(">h", self.read(2))[0]

    def write_short(self, value: int):
        self.write(struct.pack(">h", value))

    def read_ushort(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def write_ushort(self, value: int):
        self.write(struct.pack(">H", value))

    def read_int(self) -> int:
        return struct.unpack(">i", self.read(4))[0]

    def write_int(self, value: int):
        self.write(struct.pack(">i", value))

    def read_long(self) -> int:
        return struct.unpack(">q", self.read(8))[0]

    def write_long(self, value: int):
        self.write(struct.pack(">q", value))

    def read_float(self) -> float:
        return struct.unpack(">f", self.read(4))[0]

    def write_float(self, value: float):
        self.write(struct.pack(">f", value))

    def read_double(self) -> float:
        return struct.unpack(">d", self.read(8))[0]

    def write_double(self, value: float):
        self.write(struct.pack(">d", value))

    def read_bool(self) -> bool:
        return self.read_byte() == 1

    def write_bool(self, value: bool):
        self.write_byte(1 if value else 0)

    # ===== 字符串 =====
    def read_string(self) -> str:
        """现代格式：VarInt长度前缀 + UTF-8"""
        length = self.read_varint()
        return self.read(length).decode("utf-8")

    def write_string(self, value: str):
        data = value.encode("utf-8")
        self.write_varint(len(data))
        self.write(data)

    def read_string_152(self) -> str:
        """1.5.2 格式：ushort长度前缀 + UTF-16BE"""
        length = self.read_ushort()
        return self.read(length * 2).decode("utf-16-be")

    def write_string_152(self, value: str):
        data = value.encode("utf-16-be")
        self.write_ushort(len(value))
        self.write(data)

    # ===== UUID =====
    def read_uuid(self) -> str:
        """读取 16 字节二进制 UUID，返回标准带横线字符串"""
        uuid_bytes = self.read(16)
        hex_str = uuid_bytes.hex()
        return "-".join([
            hex_str[0:8],
            hex_str[8:12],
            hex_str[12:16],
            hex_str[16:20],
            hex_str[20:32]
        ])

    def write_uuid(self, uuid_str: str):
        """写入标准 UUID 字符串，转为 16 字节大端二进制"""
        hex_str = uuid_str.replace("-", "")
        self.write(bytes.fromhex(hex_str))