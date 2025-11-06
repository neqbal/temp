# PyTunnel: Project Features and Technical Analysis

## Summary of Features

This document provides a detailed breakdown of the features implemented in the PyTunnel project.

-   **Core Tunneling**: Establishes a client-server architecture to forward IP packets over a secure UDP channel.
-   **Cryptographic Subsystem**: Implements a modern cryptographic handshake (Noise-like) for key derivation and uses authenticated encryption for all data traffic.
-   **DDoS Mitigation**: Protects the server from resource exhaustion attacks via a stateless cookie mechanism.
-   **Replay Attack Prevention**: Secures data channels against replay attacks using a sliding window bitmap.
-   **Operating System Integration**: Creates and configures virtual TUN network interfaces to transparently route OS-level traffic.
-   **Configuration Management**: Uses simple YAML files for easy configuration of both client and server.
-   **Graphical User Interface (GUI)**: Provides optional Tkinter-based UIs for easy control of the client and server processes.
-   **Security & Testing Tools**: Includes scripts to generate cryptographic keys and simulate DDoS and replay attacks for verification purposes.

---

## 1. Core Architecture: Client-Server Tunnel

This feature establishes the fundamental client-server model for creating a secure tunnel.

-   **What it does**: The server listens for connections from multiple clients. Once a client is authenticated, a session is established, and the server can route IP packets between different clients or between a client and the server's network. The client initiates the connection and forwards local traffic through the tunnel.

-   **How it works**:
    -   The `Server` class binds to a UDP socket and listens for incoming packets. It maintains a dictionary of active sessions (`self.sessions`) keyed by the client's public IP and port, and a routing table (`self.routing_table`) keyed by the client's virtual tunnel IP.
    -   The `Client` class connects to the server's UDP port and initiates a handshake.
    -   Both client and server use a main event loop with `select.select()` to monitor for I/O on two file descriptors simultaneously: the UDP socket (for internet traffic) and the TUN interface file descriptor (for local OS traffic).
    -   When the server receives a packet from the TUN interface, it inspects the destination IP address, looks up the corresponding client session in its routing table, encrypts the packet for that client, and sends it over UDP.
    -   When either peer receives an encrypted data packet via UDP, it decrypts it and writes the plaintext IP packet to its local TUN interface, where the OS networking stack processes it.

-   **Key Files & Classes**:
    -   `src/pytunnel/server/server.py`: `Server` class, `run()` method contains the main loop.
    -   `src/pytunnel/client/client.py`: `Client` class, `run()` method contains the main loop.
    -   `src/pytunnel/server/session.py`: `Session` class holds the state for a single connected client.

---

## 2. Cryptographic Subsystem

This is the security core of PyTunnel, responsible for confidentiality, integrity, and authenticity. It is split into two main phases: key exchange and data encryption.

### 2.1. Handshake and Key Derivation

-   **What it does**: Securely establishes a pair of shared symmetric keys (one for sending, one for receiving) between the client and server for a new session. It provides Perfect Forward Secrecy.

-   **How it works**:
    1.  Both client and server have long-term **static** X25519 key pairs (like an identity).
    2.  For each new session, both client and server generate a new one-time **ephemeral** X25519 key pair.
    3.  A key derivation function (`derive_keys`) based on the Noise protocol framework performs multiple Elliptic-Curve Diffie-Hellman (ECDH) operations:
        -   `dh1 = ECDH(static_privkey, remote_static_pubkey)`
        -   `dh2 = ECDH(ephemeral_privkey, remote_ephemeral_pubkey)`
    4.  The results of these operations are concatenated and used as the input keying material (IKM) for a Key Derivation Function (HKDF).
    5.  HKDF is used to derive two separate 32-byte symmetric keys: a transmit (TX) key and a receive (RX) key. The client's TX key is the server's RX key, and vice-versa.

-   **Key Files & Functions**:
    -   `src/pytunnel/common/crypto.py`: `derive_keys()`, `generate_ephemeral_keys()`.
    -   `src/pytunnel/client/client.py`: The `handshake()` method orchestrates the client-side process.
    -   `src/pytunnel/server/server.py`: `handle_msg_init()` and `handle_msg_init_with_cookie()` orchestrate the server-side process.
-   **Dependencies**: `pynacl` (for `Box`, `PrivateKey`, `PublicKey`), `hkdf`.

### 2.2. Authenticated Data Encryption

-   **What it does**: Encrypts all IP packets sent through the tunnel, ensuring they cannot be read or tampered with by an attacker.

-   **How it works**:
    -   It uses the `nacl.secret.SecretBox` primitive, which provides Authenticated Encryption with Associated Data (AEAD) using the XSalsa20 stream cipher and Poly1305 MAC.
    -   The `Encryptor` class maintains an incrementing sequence number (`self.seq`). For each packet, it packs this 64-bit sequence number, generates a random 24-byte nonce, and encrypts the plaintext. The final payload is `[sequence_number] + [nonce] + [ciphertext]`.
    -   The `Decryptor` class receives this payload. It first unpacks the sequence number (used for replay protection). It then uses the nonce (first 24 bytes of the remaining ciphertext) to decrypt and authenticate the message. If the message has been tampered with, decryption will fail.

-   **Key Files & Classes**:
    -   `src/pytunnel/common/crypto.py`: `Encryptor` and `Decryptor` classes.
    -   These classes are instantiated in `client.py` and `session.py` and used in the `handle_tun_packet()` and `handle_udp_packet()` methods of both client and server.

---

## 3. Security Features

PyTunnel implements specific countermeasures against common network attacks.

### 3.1. DDoS Mitigation (Stateless Cookie)

-   **What it does**: Protects the server from DoS attacks where an attacker sends a flood of initial handshake packets (which are computationally expensive to process) from spoofed IP addresses.

-   **How it works**:
    1.  When the server receives an initial handshake packet (`MSG_INIT`), it **does not** perform any expensive cryptographic calculations.
    2.  Instead, it generates a stateless "cookie" by creating an HMAC-SHA256 MAC of the client's source IP and a current timestamp, using a secret key known only to the server.
    3.  It sends this cookie back to the client in a `MSG_COOKIE_CHALLENGE`.
    4.  A legitimate client will receive this cookie and send back a new handshake message, `MSG_INIT_WITH_COOKIE`, containing the cookie.
    5.  The server then verifies the cookie's MAC and timestamp. Only if it's valid does the server proceed with the expensive key derivation. This proves the client is not using a spoofed IP and mitigates flood attacks.

-   **Key Files & Classes**:
    -   `src/pytunnel/common/cookie.py`: `CookieManager` class is responsible for generating and verifying cookies.
    -   `src/pytunnel/server/server.py`: `handle_msg_init()` generates the cookie; `handle_msg_init_with_cookie()` verifies it.
-   **Dependencies**: `hmac`.

### 3.2. Replay Attack Prevention

-   **What it does**: Prevents an attacker from capturing an encrypted data packet and re-sending it later to cause a duplicate operation.

-   **How it works**:
    -   The `ReplayWindow` class implements a sliding window bitmap. It keeps track of the highest sequence number received so far (`max_seq`) and a 64-bit integer (`bitmap`).
    -   Each bit in the bitmap corresponds to a sequence number relative to `max_seq`. A '1' means the packet was received, and a '0' means it was not.
    -   When a packet arrives, its sequence number (`seq`) is checked:
        -   If `seq` is newer than `max_seq`, it's accepted, `max_seq` is updated, and the bitmap is shifted.
        -   If `seq` is within the 64-packet window behind `max_seq`, the corresponding bit in the bitmap is checked. If it's '1' (already seen), the packet is rejected. If it's '0', the bit is flipped to '1' and the packet is accepted.
        -   If `seq` is older than the window, it's rejected.

-   **Key Files & Classes**:
    -   `src/pytunnel/common/replay.py`: `ReplayWindow` class.
    -   An instance is created in `client.py` and `session.py`. The `accept()` method is called in `handle_udp_packet()` on both client and server before processing a data packet.

---

## 4. Operating System Integration (TUN Interface)

-   **What it does**: Creates a virtual network interface in the operating system, allowing PyTunnel to send and receive raw IP packets and act as a transparent layer in the network stack.

-   **How it works**:
    -   The `create_tun_interface()` function opens the special device file `/dev/net/tun` on Linux.
    -   It uses `fcntl.ioctl` with the `TUNSETIFF` request to tell the kernel to create a new virtual interface (e.g., `pytunnel0`). This operation returns a file descriptor.
    -   The `configure_tun_interface()` function then uses `subprocess` to call the `ip` command-line tool with `sudo` privileges to assign an IP address and bring the interface up.
    -   The returned file descriptor is used in the main `select()` loop. Reading from it provides raw IP packets from the OS, and writing to it injects raw IP packets into the OS.

-   **Key Files & Functions**:
    -   `src/pytunnel/common/tun.py`: `create_tun_interface()`, `configure_tun_interface()`.
-   **Dependencies**: This feature is Linux-specific and requires `root` privileges to execute.

---

## 5. Configuration Management

-   **What it does**: Allows users to configure the client and server without modifying the source code.

-   **How it works**:
    -   The client and server are configured via `client.yaml` and `server.yaml` files, respectively.
    -   These files specify the server address/port, paths to key files, and the desired virtual IP address for the tunnel interface.
    -   The server configuration also includes a list of authorized clients, mapping each client's public key to an assigned tunnel IP address. This acts as an access control list.
    -   The `load_config()` function in `config.py` uses the `PyYAML` library to parse these files into Python dictionaries.

-   **Key Files & Functions**:
    -   `src/pytunnel/config.py`: `load_config()`.
    -   `configs/client.yaml`, `configs/server.yaml`: Default configuration files.
-   **Dependencies**: `pyyaml`.

---

## 6. User Interfaces (GUI)

-   **What it does**: Provides simple graphical interfaces for starting, stopping, and monitoring the client and server.

-   **How it works**:
    -   `client_ui.py` and `server_ui.py` use Python's built-in `tkinter` library to create simple control panels.
    -   They manage the core client/server logic as a `subprocess`. This decouples the UI from the core application, preventing the UI from freezing during network operations.
    -   The UI captures the `stdout` and `stderr` of the subprocess in a separate thread and uses a `queue` to safely pass log messages to the main UI thread for display in a scrolled text box.
    -   The server UI also includes a CPU monitor using the `psutil` library.

-   **Key Files & Classes**:
    -   `client_ui.py`: `ClientUI` class.
    -   `server_ui.py`: `ServerUI` class.
-   **Dependencies**: `tkinter` (standard library), `psutil` (for server UI).

---

## 7. Developer and Testing Tools

-   **What it does**: A collection of scripts to support development, deployment, and security testing.

-   **How it works**:
    -   **Key Generation** (`scripts/genkeys.py`): Uses `pynacl` to generate valid X25519 public/private key pairs and saves them in the required base64-encoded format.
    -   **DDoS Flood Attack Simulator** (`tools/flood_attack.py`): Uses the `scapy` library to craft and send a high volume of `MSG_INIT` packets from spoofed source IPs to test the effectiveness of the server's cookie mitigation.
    -   **Replay Attack Simulator** (`tools/replay_attack.py`): Uses `scapy` to sniff the network for a valid `MSG_DATA` packet. Once captured, it sends the exact same packet again to test if the replay protection correctly identifies and drops it.

-   **Key Files**:
    -   `scripts/genkeys.py`
    -   `tools/flood_attack.py`
    -   `tools/replay_attack.py`
-   **Dependencies**: `scapy`.
