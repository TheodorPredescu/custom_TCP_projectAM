import socket
import threading
import queue
import pickle
from ctypes import cdll, c_char_p


class PeerInterface:
    def __init__(self):
        # Load the C++ shared library (assuming it's compiled as `peer.so`)
        self.peer_lib = cdll.LoadLibrary('./peer.so')
        self.peer_lib.get_messages_received.restype = c_char_p  # Set return type for the function

    def get_messages_received(self):
        """
        Call the C++ `get_messages_received` function to retrieve a message.
        """
        message = self.peer_lib.get_messages_received()
        print(f"Debug: Retrieved message from C++: {message.decode('utf-8')}")
        return message.decode('utf-8')

    def start_peer(self, port, remote_ip=None):
        """
        Start the peer in either server or client mode.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if remote_ip:
            # Client mode: Bind to a random available port
            self.sock.bind(('', 0))
            self.remote_addr = (remote_ip, port)
            self.is_connected = True
            print(f"Client connected to {remote_ip}:{port}")
        else:
            # Server mode: Bind to the specified port
            self.sock.bind(('', port))
            print(f"Server listening on port {port}")

        # Start the receiver thread
        self.running = True
        self.receiver_thread = threading.Thread(target=self.listen_for_packets, daemon=True)
        self.receiver_thread.start()

    def send_message(self, message):
        """
        Send a message to the connected peer.
        """
        if not self.is_connected:
            raise Exception("Not connected to a peer")

        packet = self.create_packet(message)
        self.sock.sendto(packet, self.remote_addr)
        print(f"Debug: Sent message '{message}' to {self.remote_addr}")

    def disconnect(self):
        """
        Disconnect the peer and stop the receiver thread.
        """
        self.running = False
        if self.receiver_thread:
            self.receiver_thread.join()
        if self.sock:
            self.sock.close()
        print("Disconnected")

    def listen_for_packets(self):
        """
        Continuously listen for incoming packets and process them.
        """
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                print(f"Debug: Received data from {addr}")
                packet = pickle.loads(data)

                if packet["type"] == "message":
                    print(f"Debug: Received message: {packet['data']}")
                elif packet["type"] == "ack":
                    print("Debug: Acknowledgment received")
                else:
                    print("Debug: Unknown packet type")
            except Exception as e:
                print(f"Error receiving packet: {e}")

    def create_packet(self, message):
        """
        Create a serialized packet for sending.
        """
        packet = {
            "type": "message",
            "data": message,
        }
        return pickle.dumps(packet)