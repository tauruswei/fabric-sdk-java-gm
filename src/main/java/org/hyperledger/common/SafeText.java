package org.hyperledger.common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Bryan
 * @date 2020-01-16
 */
public class SafeText {
    private static final Pattern pattern = Pattern.compile("(.*([/\\\\]{1}[\\.\\.]{1,2}|[\\.\\.]{1,2}[/\\\\]{1}|\\.\\.).*|\\.)");
    private static final String PATH_WHITE_LIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-=[];\\',./ ~!@#$%^&*()_+\"{}|:<>?";
    private static final String SecurityProviderClassName = BouncyCastleProvider.class.getName();
    private static final String DEFAULT_CRYPTO_SUITE_FACTORY = "org.hyperledger.fabric.sdk.security.HLSDKJCryptoSuiteFactory";

    private SafeText() {
    }

    public static boolean isSafePath(String filePath) {
        Matcher matcher = pattern.matcher(filePath);
        boolean isSafe = !matcher.matches();
        return isSafe;
    }

    private static String checkFile(String filePath) {
        if (filePath == null) {
            return null;
        } else {
            StringBuffer tmpStrBuf = new StringBuffer();

            for(int i = 0; i < filePath.length(); ++i) {
                for(int j = 0; j < "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-=[];\\',./ ~!@#$%^&*()_+\"{}|:<>?".length(); ++j) {
                    if (filePath.charAt(i) == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-=[];\\',./ ~!@#$%^&*()_+\"{}|:<>?".charAt(j)) {
                        tmpStrBuf.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-=[];\\',./ ~!@#$%^&*()_+\"{}|:<>?".charAt(j));
                        break;
                    }
                }
            }

            return tmpStrBuf.toString();
        }
    }

    public static String checkFilePath(String attributeFile) {
        String path = null;
        if (isSafePath(attributeFile)) {
            path = checkFile(attributeFile);
            return path;
        } else {
            throw new RuntimeException("Invalid file path");
        }
    }

    public static String checkSecurityProviderClassName(String className) {
        String str = null;
        if (className.equals(SecurityProviderClassName)) {
            str = SecurityProviderClassName;
            return str;
        } else {
            throw new RuntimeException("Invalid SecurityProviderClassName");
        }
    }

    public static String checkCryptoSuiteFactoryClassName(String className) {
        String str = null;
        if (className.equals(SecurityProviderClassName)) {
            str = SecurityProviderClassName;
            return str;
        } else {
            throw new RuntimeException("Invalid SecurityProviderClassName");
        }
    }
}

