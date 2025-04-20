package io.github.srinivasboini.common;

import lombok.NonNull;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.util.ResourceUtils;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class SSLSocketFactory {

    public javax.net.ssl.SSLSocketFactory createSSLSocketFactory(@NonNull String jksFile, @NonNull String jksPass) {
        javax.net.ssl.SSLSocketFactory sslSocketFactory;

        try {
            File jks = ResourceUtils.getFile(ResourceUtils.getFile(jksFile).getPath());
            SSLContext sslContext = SSLContextBuilder
                    .create()
                    .loadTrustMaterial(jks, jksPass.toCharArray())
                    .loadKeyMaterial(jks, jksPass.toCharArray(), jksPass.toCharArray())
                    .build();
            sslSocketFactory = sslContext.getSocketFactory();
        } catch (KeyManagementException | IOException | KeyStoreException | NoSuchAlgorithmException |
                 CertificateException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }

        return sslSocketFactory;

    }
}
