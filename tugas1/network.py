import json
import socket
import struct
from typing import Dict

MAX_PACKET_SIZE = 1_048_576

class ConnectionClosed(ConnectionError):
    pass

def _receive_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ConnectionClosed("Koneksi ditutup oleh pihak lain")
        data.extend(chunk)
    return bytes(data)

def send_packet(connection: socket.socket, packet: Dict[str, str]) -> None:
    encoded = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_PACKET_SIZE:
        raise ValueError("Paket terlalu besar")
    connection.sendall(struct.pack("!I", len(encoded)) + encoded)

def receive_packet(connection: socket.socket) -> Dict[str, str]:
    packet_size = struct.unpack("!I", _receive_exact(connection, 4))[0]
    if packet_size < 1 or packet_size > MAX_PACKET_SIZE:
        raise ValueError("Ukuran paket tidak valid")
    try:
        packet = json.loads(_receive_exact(connection, packet_size).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Paket JSON tidak valid") from error
    if not isinstance(packet, dict):
        raise ValueError("Paket harus berupa object JSON")
    return packet

