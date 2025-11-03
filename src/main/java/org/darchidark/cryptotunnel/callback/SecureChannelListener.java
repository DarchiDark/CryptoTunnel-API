package org.darchidark.cryptotunnel.callback;

import java.io.File;

public interface SecureChannelListener {
    void onMessage(String msg);
    void onFileReceived(File file);
}
