## CryptoTunnel API

### 1. What It Is

**CryptoTunnel** is a **secure, encrypted communication tunnel** inspired by the **WireGuard VPN protocol**. It allows two-way encrypted communication between clients and a server, supporting both text messages and file transfers. The system is lightweight, simple, and designed for educational purposes or private secure channels.

---

### 2. How Encryption Works

* **Handshake (Key Exchange)**

  1. Both client and server generate **ephemeral X25519 key pairs**.
  2. The client sends its ephemeral **public key** to the server, and the server responds with its own.
  3. Both sides compute a **shared secret** via X25519 (Elliptic Curve Diffie-Hellman).
  4. The shared secret is processed with **HKDF (HMAC-based Key Derivation Function, SHA-256)** to derive a **session key**.

* **Encryption Algorithm**

  * Uses **ChaCha20-Poly1305** for **authenticated encryption** (confidentiality + integrity).
  * Each message or file chunk uses a **unique 12-byte nonce**, preventing replay attacks.
  * **Forward secrecy** is guaranteed because ephemeral keys are rotated regularly.

* **Key Rotation**

  * Every 60 seconds, a **new session key** is derived from the same ephemeral keys.
  * This ensures that compromise of a session key does not compromise future communication.

---

### 3. Server Mechanism

* Listens on a specified TCP port.
* Accepts multiple client connections concurrently.
* Performs **handshake** with each client to establish a session key.
* Maintains a list of connected clients for **broadcasting messages or files**.
* Listens for incoming messages or files from each client asynchronously.
* Rotates session keys every 60 seconds to maintain forward secrecy.

---

### 4. Client Mechanism

* Connects to a server by IP and port.
* Performs **handshake** to generate a session key.
* Can send **encrypted messages** and **encrypted file chunks** to the server.
* Runs a background thread to **receive messages and files asynchronously**.
* Rotates its session key every 60 seconds to remain in sync with the server.

---

### 5. Usage Examples

```java
package org.darchidark.cryptotunnel;

import org.darchidark.cryptotunnel.callback.SecureChannelListener;
import org.darchidark.cryptotunnel.client.SecureChannelClient;
import org.darchidark.cryptotunnel.server.SecureChannelServer;

import java.io.File;
import java.io.IOException;

public class Usage {
    private void server_tunnel_start() {
        SecureChannelServer server = new SecureChannelServer(1111, new SecureChannelListener() {
            @Override
            public void onMessage(String msg) {
                System.out.println("Received from client: " + msg);
            }

            @Override
            public void onFileReceived(File file) {
                System.out.println("Received file from client: " + file.getName());
            }
        });

        System.out.println("Starting server...");
        try {
            server.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        server.broadcastMessage("Hello clients!");
        server.broadcastFile(new File("test.txt"));
    }

    private void client_tunnel_connect() throws Exception {
        SecureChannelClient client = new SecureChannelClient("10.0.0.1", 1111, new SecureChannelListener() {
            @Override
            public void onMessage(String msg) {
                System.out.println("Server says: " + msg);
            }

            @Override
            public void onFileReceived(File file) {
                System.out.println("Received file from server: " + file.getName());
            }
        });

        client.sendMessage("Hello server!");
        client.sendFile(new File("test.txt"));
    }
}
```

---

### 6. How to connect to your project

You can connect CryptoTunnel-API to your project, using [jitpack.io](https://jitpack.io/#DarchiDark/CryptoTunnel-API/)

```
	dependencyResolutionManagement {
		repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
		repositories {
			mavenCentral()
			maven { url = uri("https://jitpack.io") }
		}
	}

	dependencies {
	        implementation("com.github.DarchiDark:CryptoTunnel-API:Tag")
	}
```
