package org.hyperledger.fabric.sdk.security;

import java.io.Reader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.sdk.exception.CryptoException;

/**
 * @author Bryan
 * @date 2020-01-16
 */
public class PEMPrivateKeyDecoder {

    private String password = "";
    private static PEMPrivateKeyDecoder instance = null;

    private PEMPrivateKeyDecoder() {
    }

    public static PEMPrivateKeyDecoder getInstance() {
        if (instance == null) {
            instance = new PEMPrivateKeyDecoder();
        }

        return instance;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public PrivateKey getPrivateKeyFromBytes(byte[] privatkeydata) throws CryptoException {
        String data = new String(privatkeydata);
        return this.getPrivateKeyFromBytes(data);
    }

    public PrivateKey getPrivateKeyFromBytes(String privatkeydata) throws CryptoException {
        Security.addProvider(new BouncyCastleProvider());
        String data = privatkeydata;
        JcaPEMKeyConverter converter = (new JcaPEMKeyConverter()).setProvider("BC");

        try {
            if (!privatkeydata.contains("DEK-Info")) {
                PrivateKey pk = null;
                PemReader pr = new PemReader(new StringReader(data));
                PemObject po = pr.readPemObject();
                PEMParser pem = new PEMParser(new StringReader(data));
                if (po == null) {
                    throw new RuntimeException("PemObject is null");
                } else {
                    if (po.getType().equals("PRIVATE KEY")) {
                        Object keyPair = pem.readObject();
                        if (keyPair instanceof PrivateKeyInfo) {
                            pk = (new JcaPEMKeyConverter()).getPrivateKey((PrivateKeyInfo) keyPair);
                        } else if (keyPair instanceof PEMKeyPair) {
                            pk = (new JcaPEMKeyConverter()).getPrivateKey(((PEMKeyPair) keyPair).getPrivateKeyInfo());
                        } else {
                            System.out.println("keyPair instanceof  of not PrivateKeyInfo or PEMKeyPair");
                        }
                    } else {
                        PEMKeyPair kp = (PEMKeyPair) pem.readObject();
                        System.out.println("(PEMKeyPair) pem.readObject");
                        if (kp == null) {
                            System.out.println("PEMKeyPair is null");
                            throw new RuntimeException("PEMKeyPair is null");
                        }

                        pk = (new JcaPEMKeyConverter()).getPrivateKey(kp.getPrivateKeyInfo());
                    }

                    return pk;
                }
            } else {
                System.out.println("the privatkeydata contains DEK-Info");
                if (privatkeydata.contains("-----BEGIN PRIVATE KEY-----") || privatkeydata
                    .contains("-----END PRIVATE KEY-----")) {
                    data = privatkeydata.replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----");
                    data = data.replace("-----END PRIVATE KEY-----", "-----END EC PRIVATE KEY-----");
                }

                Reader pemReader = new StringReader(data);
                PEMParser pemParser = new PEMParser(pemReader);
                Object object = pemParser.readObject();
                if (object instanceof PEMEncryptedKeyPair) {
                    PEMEncryptedKeyPair pemEncryptedKeyPair = (PEMEncryptedKeyPair) object;
                    PEMDecryptorProvider decProv = (new JcePEMDecryptorProviderBuilder())
                        .build(this.password.toCharArray());
                    PEMKeyPair pemkp = pemEncryptedKeyPair.decryptKeyPair(decProv);
                    KeyPair kp = converter.getKeyPair(pemkp);
                    return kp.getPrivate();
                } else {
                    throw new CryptoException("Unable to generate key pair");
                }
            }
        } catch (Exception var11) {
            System.out.println("get PrivateKeyFromBytes Error execption");
            throw new CryptoException("get PrivateKeyFromBytes Error", var11);
        }
    }

    public static void main(String[] args) throws Exception {
        String pwd = "123456789";
        PEMPrivateKeyDecoder decoder = getInstance();
        decoder.setPassword(pwd);
        String encryptfile1 = "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,90be14b32a1c4cbb937006ba1189f73a\n\nwYrJIV6/T+czrHZQW2mKqWOU/HywjSwho+dBKAwNQw99M15JU0bvZvIyUFRztcS5\n5qqvrASRIj1caTJgE4rkwxotvlmtPJ7PKqPHqGTeIy6Ccxn75ZLWJf7aKCIJVb42\n3RLz8YGDfdCdSEJoC88lf0920lTduUO53AiEsGCBlYw=\n-----END EC PRIVATE KEY-----";
        String encryptfile2 = "-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,90be14b32a1c4cbb937006ba1189f73a\n\nwYrJIV6/T+czrHZQW2mKqWOU/HywjSwho+dBKAwNQw99M15JU0bvZvIyUFRztcS5\n5qqvrASRIj1caTJgE4rkwxotvlmtPJ7PKqPHqGTeIy6Ccxn75ZLWJf7aKCIJVb42\n3RLz8YGDfdCdSEJoC88lf0920lTduUO53AiEsGCBlYw=\n-----END PRIVATE KEY-----";
        String plaintextSK = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgG9e4BortkeIR7oeI\npAQIU6waiwFqMTR97GrBQY6VAvOhRANCAASG9IKUc2wB3UYZ7hmY+JuKsULzzFYT\nFkMnXmEd/3HRyFVvxzR8KcupVTC890oqPRaCUT+m3YkX0lYy9GIhcFl1\n-----END PRIVATE KEY-----";
        String utf8Str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMzDHGUim1THu/cf3\n9BxYd62m/Z+vYQ0uNeV+xAVZaC+hRANCAAShQe3oJ/nYZ7XwL2zZsF/4OpMbL0sP\ntQ2FXnNMYfJWf4hvcllml9JNGvV7JPautiM6QZSrS5H23ocotZmlbHGj\n-----END PRIVATE KEY-----\n";
        System.out.printf("%s\n", decoder.getPrivateKeyFromBytes(plaintextSK));
    }
}

