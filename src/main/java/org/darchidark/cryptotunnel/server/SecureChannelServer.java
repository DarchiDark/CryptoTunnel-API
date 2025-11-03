package org.darchidark.cryptotunnel.server;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.darchidark.cryptotunnel.callback.SecureChannelListener;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SecureChannelServer {
    private final int port;
    private final SecureChannelListener listener;
    private final Set<ClientConnection> clients = Collections.synchronizedSet(new HashSet<>());

    public SecureChannelServer(int port, SecureChannelListener listener) {
        this.port = port;
        this.listener = listener;
    }

    public void start() throws IOException {
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("[CryptoTunnel] Server listening on port " + port);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("[CryptoTunnel] Client from " + clientSocket.getInetAddress().getHostAddress() + " connected.");
            new Thread(() -> handleClient(clientSocket)).start();
        }
    }

    private void handleClient(Socket socket) {
        try (Socket s = socket;
             DataInputStream dataIn = new DataInputStream(s.getInputStream());
             DataOutputStream dataOut = new DataOutputStream(s.getOutputStream())) {

            SecureRandom random = new SecureRandom();
            byte[] nonce = new byte[12];
            long nonceCounter = 0;

            X25519PrivateKeyParameters ephPriv = new X25519PrivateKeyParameters(random);
            X25519PublicKeyParameters ephPub = ephPriv.generatePublicKey();

            byte[] clientEphPubBytes = new byte[32];
            dataIn.readFully(clientEphPubBytes);
            X25519PublicKeyParameters clientEphPub = new X25519PublicKeyParameters(clientEphPubBytes, 0);

            dataOut.write(ephPub.getEncoded());
            dataOut.flush();

            byte[] sharedSecret = new byte[32];
            ephPriv.generateSecret(clientEphPub, sharedSecret, 0);

            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(sharedSecret, null, null));
            byte[] sessionKeyBytes = new byte[32];
            hkdf.generateBytes(sessionKeyBytes, 0, 32);
            SecretKeySpec keySpec = new SecretKeySpec(sessionKeyBytes, "ChaCha20");

            ClientConnection clientConn = new ClientConnection(dataOut, keySpec);
            clients.add(clientConn);

            new Thread(() -> rotateKey(clientConn, ephPriv, ephPub, clientEphPub)).start();

            while (true) {
                int type = dataIn.readInt();
                int len;
                byte[] buffer;
                Cipher cipher;

                switch (type) {
                    case 0:
                        len = dataIn.readInt();
                        buffer = new byte[len];
                        dataIn.readFully(buffer);
                        System.arraycopy(longToBytes(nonceCounter), 0, nonce, 0, 8);
                        cipher = Cipher.getInstance("ChaCha20-Poly1305");
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(nonce));
                        byte[] plaintext = cipher.doFinal(buffer);
                        listener.onMessage(new String(plaintext));
                        nonceCounter++;
                        break;
                    case 1:
                        String filename = dataIn.readUTF();
                        long fileSize = dataIn.readLong();
                        File file = new File("recv_" + filename);
                        FileOutputStream fos = new FileOutputStream(file);
                        long received = 0;
                        while (received < fileSize) {
                            len = dataIn.readInt();
                            buffer = new byte[len];
                            dataIn.readFully(buffer);
                            System.arraycopy(longToBytes(nonceCounter), 0, nonce, 0, 8);
                            cipher = Cipher.getInstance("ChaCha20-Poly1305");
                            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(nonce));
                            plaintext = cipher.doFinal(buffer);
                            fos.write(plaintext);
                            received += plaintext.length;
                            nonceCounter++;
                        }
                        fos.close();
                        listener.onFileReceived(file);
                        break;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void broadcastMessage(String msg) {
        synchronized (clients) {
            for (ClientConnection client : clients) {
                try { client.sendMessage(msg); } catch (Exception ignored) {}
            }
        }
    }

    public void broadcastFile(File file) {
        synchronized (clients) {
            for (ClientConnection client : clients) {
                try { client.sendFile(file); } catch (Exception ignored) {}
            }
        }
    }

    private void rotateKey(ClientConnection client, X25519PrivateKeyParameters ephPriv,
                           X25519PublicKeyParameters ephPub, X25519PublicKeyParameters clientEphPub) {
        while (true) {
            try {
                Thread.sleep(60_000);
                byte[] newShared = new byte[32];
                ephPriv.generateSecret(clientEphPub, newShared, 0);
                HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
                hkdf.init(new HKDFParameters(newShared, null, null));
                byte[] newSession = new byte[32];
                hkdf.generateBytes(newSession, 0, 32);
                client.keySpec = new SecretKeySpec(newSession, "ChaCha20");
            } catch (Exception ignored) {}
        }
    }

    private static byte[] longToBytes(long val) {
        byte[] arr = new byte[8];
        for (int i = 0; i < 8; i++) arr[7 - i] = (byte) (val >>> (i * 8));
        return arr;
    }

    public static class ClientConnection {
        DataOutputStream out;
        SecretKeySpec keySpec;
        long nonceCounter = 0;

        public ClientConnection(DataOutputStream out, SecretKeySpec keySpec) {
            this.out = out;
            this.keySpec = keySpec;
        }

        public synchronized void sendMessage(String msg) throws Exception {
            byte[] plaintext = msg.getBytes();
            byte[] nonce = new byte[12];
            System.arraycopy(longToBytes(nonceCounter), 0, nonce, 0, 8);
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
            byte[] ciphertext = cipher.doFinal(plaintext);
            out.writeInt(0);
            out.writeInt(ciphertext.length);
            out.write(ciphertext);
            nonceCounter++;
        }

        public synchronized void sendFile(File file) throws Exception {
            FileInputStream fis = new FileInputStream(file);
            out.writeInt(1);
            out.writeUTF(file.getName());
            out.writeLong(file.length());

            byte[] buffer = new byte[1024];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                byte[] chunk = new byte[read];
                System.arraycopy(buffer, 0, chunk, 0, read);
                byte[] nonce = new byte[12];
                System.arraycopy(longToBytes(nonceCounter), 0, nonce, 0, 8);
                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
                byte[] ciphertext = cipher.doFinal(chunk);
                out.writeInt(ciphertext.length);
                out.write(ciphertext);
                nonceCounter++;
            }
            fis.close();
        }
    }
}
