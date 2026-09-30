import socket
from config import PORT, SHARED_KEY, VERBOSE
from des import CryptoError, decrypt_message, encrypt_message
from network import ConnectionClosed, receive_packet, send_packet

def run_sender() -> None:
    receiver_ip = input("IP receiver [127.0.0.1]: ").strip() or "127.0.0.1"

    with socket.create_connection((receiver_ip, PORT)) as connection:
        print(f"Terhubung ke receiver {receiver_ip}:{PORT}")
        print("Sender mengirim lebih dahulu. Ketik /quit untuk selesai.\n")

        while True:
            message = input("Anda (sender)   : ")
            packet = encrypt_message(message, SHARED_KEY, verbose=VERBOSE)
            send_packet(connection, packet)
            print(f"Dikirim (cipher) : {packet['ciphertext']}\n")
            if message == "/quit":
                break

            packet = receive_packet(connection)
            print(f"Diterima (cipher): {packet['ciphertext']}")
            reply = decrypt_message(packet, SHARED_KEY, verbose=VERBOSE)
            print(f"Receiver (plain) : {reply}\n")
            if reply == "/quit":
                break

def main() -> None:
    try:
        run_sender()
    except ConnectionRefusedError:
        print("Gagal terhubung. Jalankan receiver.py terlebih dahulu.")
    except (ConnectionClosed, ConnectionError, OSError) as error:
        print(f"Koneksi berakhir: {error}")
    except (CryptoError, ValueError) as error:
        print(f"Paket ditolak: {error}")
    except KeyboardInterrupt:
        print("\nProgram dihentikan.")

if __name__ == "__main__":
    main()

