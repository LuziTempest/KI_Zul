from __future__ import annotations
import secrets
from typing import Dict, List, Sequence, Tuple

IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
)

FP = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
)

EXPANSION = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
)

P = (
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
)

PC1 = (
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
)

PC2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
)

SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

SBOX = (
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)


def _permute(value: int, table: Sequence[int], input_bits: int) -> int:
    output = 0
    for position in table:
        output = (output << 1) | ((value >> (input_bits - position)) & 1)
    return output

def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))

def parse_hex_key(text: str) -> bytes:
    cleaned = "".join(text.split())
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 16:
        raise ValueError("Key DES harus tepat 16 digit heksadesimal (8 byte)")
    try:
        key = bytes.fromhex(cleaned)
    except ValueError as error:
        raise ValueError("Key hanya boleh berisi digit heksadesimal 0-9/A-F") from error
    if len(key) != 8:
        raise ValueError("Key DES harus tepat 8 byte")
    return key

def generate_iv() -> bytes:
    """Membuat IV CBC baru. secrets hanya untuk random byte, bukan algoritma DES."""
    return secrets.token_bytes(8)

class CryptoError(ValueError):
    """Ciphertext atau paket tidak valid."""

class DES:
    BLOCK_SIZE = 8

    def __init__(self, key: bytes):
        if len(key) != self.BLOCK_SIZE:
            raise ValueError("Key DES harus berukuran 8 byte")
        self.round_keys = self._create_round_keys(int.from_bytes(key, "big"))

    @staticmethod
    def _create_round_keys(key: int) -> Tuple[int, ...]:
        permuted = _permute(key, PC1, 64)
        left = (permuted >> 28) & 0x0FFFFFFF
        right = permuted & 0x0FFFFFFF
        keys = []
        for shift in SHIFTS:
            left = ((left << shift) | (left >> (28 - shift))) & 0x0FFFFFFF
            right = ((right << shift) | (right >> (28 - shift))) & 0x0FFFFFFF
            keys.append(_permute((left << 28) | right, PC2, 56))
        return tuple(keys)

    @staticmethod
    def _feistel(right: int, round_key: int) -> int:
        expanded = _permute(right, EXPANSION, 32) ^ round_key
        substituted = 0
        for box_number in range(8):
            six_bits = (expanded >> (42 - 6 * box_number)) & 0x3F
            row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01)
            column = (six_bits >> 1) & 0x0F
            substituted = (substituted << 4) | SBOX[box_number][row][column]
        return _permute(substituted, P, 32)

    def _crypt_block(
        self, block: bytes, decrypt: bool, with_trace: bool
    ) -> Tuple[bytes, List[str]]:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError("Satu blok DES harus berukuran 8 byte")

        initial = _permute(int.from_bytes(block, "big"), IP, 64)
        left = (initial >> 32) & 0xFFFFFFFF
        right = initial & 0xFFFFFFFF
        keys = tuple(reversed(self.round_keys)) if decrypt else self.round_keys

        trace = []
        if with_trace:
            trace.append("Decryption" if decrypt else "Encryption")
            trace.append(f"After initial permutation {initial:016X}")

        for round_number, round_key in enumerate(keys, start=1):
            left, right = right, left ^ self._feistel(right, round_key)
            if with_trace:
                shown_left, shown_right = (right, left) if round_number == 16 else (left, right)
                trace.append(
                    f"Round  {round_number:<2}  {shown_left:08X}   "
                    f"{shown_right:08X}   {round_key:012X}"
                )

        pre_output = (right << 32) | left
        output = _permute(pre_output, FP, 64).to_bytes(8, "big")
        if with_trace:
            label = "Plain Text" if decrypt else "Cipher Text"
            trace.append(f"{label} :  {output.hex().upper()}")
        return output, trace

    def encrypt_block(self, block: bytes, with_trace: bool = False) -> Tuple[bytes, List[str]]:
        return self._crypt_block(block, decrypt=False, with_trace=with_trace)

    def decrypt_block(self, block: bytes, with_trace: bool = False) -> Tuple[bytes, List[str]]:
        return self._crypt_block(block, decrypt=True, with_trace=with_trace)

    def encrypt_cbc(
        self, plaintext: bytes, iv: bytes, with_trace: bool = False
    ) -> Tuple[bytes, str]:
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError("IV DES-CBC harus berukuran 8 byte")

        padding = self.BLOCK_SIZE - (len(plaintext) % self.BLOCK_SIZE)
        padded = plaintext + bytes([padding]) * padding
        ciphertext = bytearray()
        previous = iv
        flow: List[str] = []

        for offset in range(0, len(padded), self.BLOCK_SIZE):
            block_number = offset // self.BLOCK_SIZE + 1
            plain_block = padded[offset : offset + self.BLOCK_SIZE]
            des_input = _xor_bytes(plain_block, previous)
            encrypted, block_trace = self.encrypt_block(des_input, with_trace)
            ciphertext.extend(encrypted)

            if with_trace:
                chaining_label = "IV" if block_number == 1 else "Previous Cipher"
                flow.extend(
                    [
                        "=" * 72,
                        f"CBC Encryption Block {block_number}",
                        f"Plain Block       : {plain_block.hex().upper()}",
                        f"{chaining_label:<17} : {previous.hex().upper()}",
                        f"DES Input (XOR)   : {des_input.hex().upper()}",
                        *block_trace,
                    ]
                )
            previous = encrypted

        return bytes(ciphertext), "\n".join(flow)

    def decrypt_cbc(
        self, ciphertext: bytes, iv: bytes, with_trace: bool = False
    ) -> Tuple[bytes, str]:
        if len(iv) != self.BLOCK_SIZE:
            raise ValueError("IV DES-CBC harus berukuran 8 byte")
        if not ciphertext or len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext DES-CBC harus berupa kelipatan 8 byte")

        padded_plaintext = bytearray()
        previous = iv
        flow: List[str] = []

        for offset in range(0, len(ciphertext), self.BLOCK_SIZE):
            block_number = offset // self.BLOCK_SIZE + 1
            cipher_block = ciphertext[offset : offset + self.BLOCK_SIZE]
            des_output, block_trace = self.decrypt_block(cipher_block, with_trace)
            plain_block = _xor_bytes(des_output, previous)
            padded_plaintext.extend(plain_block)

            if with_trace:
                chaining_label = "IV" if block_number == 1 else "Previous Cipher"
                flow.extend(
                    [
                        "=" * 72,
                        f"CBC Decryption Block {block_number}",
                        f"Cipher Block      : {cipher_block.hex().upper()}",
                        f"{chaining_label:<17} : {previous.hex().upper()}",
                        *block_trace,
                        f"CBC Output (XOR)  : {plain_block.hex().upper()}",
                    ]
                )
            previous = cipher_block

        padding = padded_plaintext[-1]
        if padding < 1 or padding > self.BLOCK_SIZE:
            raise ValueError("Padding tidak valid; key salah atau data rusak")
        if padded_plaintext[-padding:] != bytes([padding]) * padding:
            raise ValueError("Padding tidak valid; key salah atau data rusak")
        return bytes(padded_plaintext[:-padding]), "\n".join(flow)


def encrypt_message(message: str, key: bytes, verbose: bool = False) -> Dict[str, str]:
    """Enkripsi teks menjadi paket IV dan ciphertext berbentuk heksadesimal."""
    des = DES(key)
    iv = generate_iv()
    plaintext = message.encode("utf-8")
    ciphertext, flow = des.encrypt_cbc(plaintext, iv, with_trace=verbose)

    if verbose:
        print("\n==================== ENCRYPTION ====================")
        print(f"Plain Text             : {message}")
        print(f"Plain Text (UTF-8 hex) : {plaintext.hex().upper() or '(empty)'}")
        print(f"CBC IV                 : {iv.hex().upper()}")
        print(flow)
        print(f"Cipher Text            : {ciphertext.hex().upper()}")
        print("====================================================\n")

    return {
        "iv": iv.hex().upper(),
        "ciphertext": ciphertext.hex().upper(),
    }

def decrypt_message(packet: Dict[str, str], key: bytes, verbose: bool = False) -> str:
    """Dekripsi paket IV dan ciphertext kembali menjadi teks UTF-8."""
    try:
        iv_text = packet["iv"]
        ciphertext_text = packet["ciphertext"]
        if not isinstance(iv_text, str) or not isinstance(ciphertext_text, str):
            raise TypeError
        iv = bytes.fromhex(iv_text)
        ciphertext = bytes.fromhex(ciphertext_text)
    except (KeyError, TypeError, ValueError) as error:
        raise CryptoError("Format paket terenkripsi tidak valid") from error

    try:
        des = DES(key)
        plaintext, flow = des.decrypt_cbc(ciphertext, iv, with_trace=verbose)
        message = plaintext.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise CryptoError("Key salah atau ciphertext rusak") from error

    if verbose:
        print("\n==================== DECRYPTION ====================")
        print(f"Cipher Text            : {ciphertext.hex().upper()}")
        print(f"CBC IV                 : {iv.hex().upper()}")
        print(flow)
        print(f"Plain Text (UTF-8 hex) : {plaintext.hex().upper() or '(empty)'}")
        print(f"Plain Text             : {message}")
        print("====================================================\n")

    return message

def _demo() -> None:
    """Contoh satu blok yang sama dengan vektor pada soal."""
    key = parse_hex_key("AABB09182736CCDD")
    plaintext = bytes.fromhex("123456ABCD132536")
    des = DES(key)

    ciphertext, encryption_flow = des.encrypt_block(plaintext, with_trace=True)
    print("\n".join(encryption_flow))
    print()
    recovered, decryption_flow = des.decrypt_block(ciphertext, with_trace=True)
    print("\n".join(decryption_flow))

    if recovered != plaintext:
        raise RuntimeError("Demo DES gagal")

if __name__ == "__main__":
    _demo()
