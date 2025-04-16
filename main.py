from interface import PeerInterface


def run_server(port):
    """
    Run the peer in server mode.
    """
    server = PeerInterface()

    print(f"Server is running on port {port}. Waiting for messages...")
    try:
        while True:
            # Use the C++ `get_messages_received` function to retrieve messages
            message = server.get_messages_received()
            print(f"Server received: {message}")
    except KeyboardInterrupt:
        print("Shutting down server...")


def run_client(port, remote_ip):
    """
    Run the peer in client mode.
    """
    print(f"Client is connected to server at {remote_ip}:{port}.")
    try:
        while True:
            # Send a message to the server
            message = input("Enter a message to send to the server (or 'exit' to quit): ")
            if message.lower() == "exit":
                break
            print(f"Client sent: {message}")
    except KeyboardInterrupt:
        print("Shutting down client...")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 main.py <mode> [<remote_ip>] [<port>]")
        print("Modes:")
        print("  server <port>       Run as server on the specified port.")
        print("  client <remote_ip> <port>  Run as client connecting to the specified server and port.")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "server":
        if len(sys.argv) != 3:
            print("Usage: python3 main.py server <port>")
            sys.exit(1)
        port = int(sys.argv[2])
        run_server(port)
    elif mode == "client":
        if len(sys.argv) != 4:
            print("Usage: python3 main.py client <remote_ip> <port>")
            sys.exit(1)
        remote_ip = sys.argv[2]
        port = int(sys.argv[3])
        run_client(port, remote_ip)
    else:
        print("Invalid mode. Use 'server' or 'client'.")
        sys.exit(1)