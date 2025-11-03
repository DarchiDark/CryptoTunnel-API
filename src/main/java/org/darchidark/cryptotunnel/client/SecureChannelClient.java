package org.darchidark.cryptotunnel.client;

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
import java.net.Socket;
import java.security.SecureRandom;

public class SecureChannelClient {
    private final Socket socket;
    private final DataInputStream dataIn;
    private final DataOutputStream dataOut;
    private SecretKeySpec keySpec;
    private long nonceCounter;
    private final byte[] nonce = new byte[12];
    private final SecureRandom random = new SecureRandom();
    private final SecureChannelListener listener;

    public SecureChannelClient(String host, int port, SecureChannelListener listener) throws Exception {
        this.listener = listener;
        socket = new Socket(host, port);
        dataIn = new DataInputStream(socket.getInputStream());
        dataOut = new DataOutputStream(socket.getOutputStream());
        handshake();
        startReceiver();
        startKeyRotation();
    }

    private void handshake() throws Exception {
        X25519PrivateKeyParameters ephPriv = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters ephPub = ephPriv.generatePublicKey();

        dataOut.write(ephPub.getEncoded());
        dataOut.flush();

        byte[] serverEphPubBytes = new byte[32];
        dataIn.readFully(serverEphPubBytes);
        X25519PublicKeyParameters serverEphPub = new X25519PublicKeyParameters(serverEphPubBytes, 0);

        byte[] sharedSecret = new byte[32];
        ephPriv.generateSecret(serverEphPub, sharedSecret, 0);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedSecret, null, null));
        byte[] sessionKeyBytes = new byte[32];
        hkdf.generateBytes(sessionKeyBytes, 0, 32);
        keySpec = new SecretKeySpec(sessionKeyBytes, "ChaCha20");
        nonceCounter = 0;
    }

    private void startReceiver() {
        new Thread(() -> {
            try {
                while (!socket.isClosed()) {
                    int type = dataIn.readInt();
                    int len;
                    byte[] buffer;
                    switch (type) {
                        case 0:
                            len = dataIn.readInt();
                            buffer = new byte[len];
                            dataIn.readFully(buffer);

                            System.arraycopy(longToBytes(nonceCounter), 0, nonce, 0, 8);
                            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
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
        }).start();
    }

    private void startKeyRotation() {
        Thread keyRotationThread = new Thread(() -> {
            while (!socket.isClosed()) {
                try {
                    Thread.sleep(60_000);
                    handshake();
                } catch (Exception ignored) {}
            }
        });
        keyRotationThread.setDaemon(true);
        keyRotationThread.start();
    }

    public void sendMessage(String msg) throws Exception {
        byte[] plaintext = msg.getBytes();
        byte[] ciphertext;

        synchronized (keySpec) {
            System.arraycopy(longToBytes(nonceCounter), 0, nonce, 0, 8);
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
            ciphertext = cipher.doFinal(plaintext);
            nonceCounter++;
        }

        dataOut.writeInt(0);
        dataOut.writeInt(ciphertext.length);
        dataOut.write(ciphertext);
    }

    public void sendFile(File file) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        dataOut.writeInt(1);
        dataOut.writeUTF(file.getName());
        dataOut.writeLong(file.length());

        byte[] buffer = new byte[1024];
        int read;
        while ((read = fis.read(buffer)) != -1) {
            byte[] chunk = new byte[read];
            System.arraycopy(buffer, 0, chunk, 0, read);

            byte[] ciphertext;
            synchronized (keySpec) {
                System.arraycopy(longToBytes(nonceCounter), 0, nonce, 0, 8);
                Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
                ciphertext = cipher.doFinal(chunk);
                nonceCounter++;
            }

            dataOut.writeInt(ciphertext.length);
            dataOut.write(ciphertext);
        }
        fis.close();
    }

    public void close() throws IOException {
        socket.close();
    }

    private static byte[] longToBytes(long val) {
        byte[] arr = new byte[8];
        for (int i = 0; i < 8; i++) arr[7 - i] = (byte) (val >>> (i * 8));
        return arr;
    }
}
