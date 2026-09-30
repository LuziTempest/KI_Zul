import socket
from config import HOST, PORT, SHARED_KEY, VERBOSE
from des import CryptoError, decrypt_message, encrypt_message
from network import ConnectionClosed, receive_packet, send_packet

def run_receiver() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"Receiver aktif pada port {PORT}, menunggu sender...")

        connection, address = server.accept()
        with connection:
            print(f"Sender terhubung dari {address[0]}:{address[1]}")
            print("Receiver menerima lebih dahulu. Ketik /quit untuk selesai.\n")

            while True:
                packet = receive_packet(connection)
                print(f"Diterima (cipher): {packet['ciphertext']}")
                message = decrypt_message(packet, SHARED_KEY, verbose=VERBOSE)
                print(f"Sender (plain)    : {message}\n")
                if message == "/quit":
                    break

                reply = input("Anda (receiver) : ")
                packet = encrypt_message(reply, SHARED_KEY, verbose=VERBOSE)
                send_packet(connection, packet)
                print(f"Dikirim (cipher) : {packet['ciphertext']}\n")
                if reply == "/quit":
                    break

def main() -> None:
    try:
        run_receiver()
    except (ConnectionClosed, ConnectionError, OSError) as error:
        print(f"Koneksi berakhir: {error}")
    except (CryptoError, ValueError) as error:
        print(f"Paket ditolak: {error}")
    except KeyboardInterrupt:
        print("\nProgram dihentikan.")

if __name__ == "__main__":
    main()

