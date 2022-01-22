package org.fuin.dddcqrsunit;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.fuin.ddd4j.ddd.DecryptionFailedException;
import org.fuin.ddd4j.ddd.DuplicateEncryptionKeyIdException;
import org.fuin.ddd4j.ddd.EncryptedData;
import org.fuin.ddd4j.ddd.EncryptedDataService;
import org.fuin.ddd4j.ddd.EncryptionKeyIdUnknownException;
import org.fuin.ddd4j.ddd.EncryptionKeyVersionUnknownException;
import org.fuin.utils4j.Utils4J;

/**
 * Simple in-memory crypto service for testing purposes.
 */
public final class InMemoryCryptoService implements EncryptedDataService {

    /** Key the hash map that has a byte array (byte[]) as value that contains the salt to use for key creation. */
    public static final String PARAM_SALT = "salt";

    /** Key the hash map that has a character array (char[]) as value that contains the password to use for key creation. */
    public static final String PARAM_PASSWORD = "password";

    private Set<String> keyIds;

    private Map<String, Map<Integer, Key>> keys;

    /**
     * Default constructor.
     */
    public InMemoryCryptoService() {
        super();
        this.keyIds = new HashSet<>();
        this.keys = new HashMap<>();
    }

    /**
     * Creates a new entry.
     * 
     * @param keyId
     *            Unique key identifier.
     * @param pw
     *            Password to use for secret key creation.
     * @param salt
     *            Salt to use for key creation.
     */
    private void createEntry(final String keyId, final char[] pw, final byte[] salt) {
        nextKey(keyId, pw, salt);
        keyIds.add(keyId);
    }

    private int nextKey(final String keyId, final char[] pw, final byte[] salt) {
        final Map<Integer, Key> keyVersions = keys.computeIfAbsent(keyId, k -> new HashMap<>());
        final int nextVersion = calculateNextVersion(keyVersions);
        keyVersions.computeIfAbsent(nextVersion, k -> new Key(createSecretKey(pw, salt), createIvParameterSpec()));
        return nextVersion;
    }

    private static Integer findLatestVersion(final Map<Integer, ?> map) {
        int latestVersion = 0;
        final Iterator<Integer> it = map.keySet().iterator();
        while (it.hasNext()) {
            final Integer version = it.next();
            if (version > latestVersion) {
                latestVersion = version;
            }
        }
        return latestVersion;
    }

    private static int calculateNextVersion(final Map<Integer, ?> map) {
        return findLatestVersion(map) + 1;
    }

    private static IvParameterSpec createIvParameterSpec() {
        final byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    private static SecretKey createSecretKey(final char[] pw, final byte[] salt) {
        try {
            final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final KeySpec spec = new PBEKeySpec(pw, salt, 65536, 256);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException("Failed to create secret key", ex);
        }
    }

    @Override
    public boolean keyExists(@NotEmpty String keyId) {
        return keyIds.contains(keyId);
    }

    @Override
    public void createKey(@NotEmpty String keyId, Map<String, Object> params) throws DuplicateEncryptionKeyIdException {
        Utils4J.checkNotEmpty(keyId, keyId);
        if (keyIds.contains(keyId)) {
            throw new DuplicateEncryptionKeyIdException(keyId);
        }
        final PwSalt result = verifyParams(params);
        createEntry(keyId, result.getPw(), result.getSalt());
    }

    @Override
    public String rotateKey(@NotEmpty String keyId, Map<String, Object> params) throws EncryptionKeyIdUnknownException {
        Utils4J.checkNotEmpty(keyId, keyId);
        if (!keyIds.contains(keyId)) {
            throw new EncryptionKeyIdUnknownException(keyId);
        }
        final PwSalt result = verifyParams(params);
        return "" + nextKey(keyId, result.getPw(), result.getSalt());
    }

    @Override
    public String getKeyVersion(@NotEmpty String keyId) throws EncryptionKeyIdUnknownException {
        Utils4J.checkNotEmpty(keyId, keyId);
        if (!keyIds.contains(keyId)) {
            throw new EncryptionKeyIdUnknownException(keyId);
        }
        final Map<Integer, Key> keyVersions = keys.get(keyId);
        return "" + findLatestVersion(keyVersions);
    }

    @Override
    public EncryptedData encrypt(@NotEmpty String keyId, @NotEmpty String dataType, @NotEmpty String contentType, @NotEmpty byte[] data)
            throws EncryptionKeyIdUnknownException {

        if (!keyIds.contains(keyId)) {
            throw new EncryptionKeyIdUnknownException(keyId);
        }

        final Map<Integer, Key> keyVersions = keys.get(keyId);
        final int keyVersion = findLatestVersion(keyVersions);
        final Key key = keyVersions.get(keyVersion);
        final SecretKey secretKey = key.getSecretKey();
        final IvParameterSpec ivParameterSpec = key.getIvParameterSpec();

        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedData = cipher.doFinal(data);
            return new EncryptedData(keyId, "" + keyVersion, dataType, contentType, encryptedData);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException ex) {
            throw new RuntimeException("Failed to encrypt data of type '" + dataType + "' with key '" + keyId + "'", ex);
        }

    }

    @Override
    public @NotEmpty byte[] decrypt(@NotNull EncryptedData encryptedData)
            throws EncryptionKeyIdUnknownException, EncryptionKeyVersionUnknownException, DecryptionFailedException {

        final String keyId = encryptedData.getKeyId();
        if (!keyIds.contains(keyId)) {
            throw new EncryptionKeyIdUnknownException(keyId);
        }

        final Map<Integer, Key> keyVersions = keys.get(keyId);
        final int keyVersion = Integer.parseInt(encryptedData.getKeyVersion());
        final Key key = keyVersions.get(keyVersion);
        if (key == null) {
            throw new EncryptionKeyVersionUnknownException(encryptedData.getKeyVersion());
        }
        final SecretKey secretKey = key.getSecretKey();
        final IvParameterSpec ivParameterSpec = key.getIvParameterSpec();

        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(encryptedData.getEncryptedData());
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new DecryptionFailedException();
        }

    }

    private PwSalt verifyParams(final Map<String, Object> params) {
        if (params == null || params.isEmpty()) {
            throw new IllegalArgumentException("The implementation requires parameters, but got none");
        }
        final Object pwObj = params.get(PARAM_PASSWORD);
        if (pwObj == null) {
            throw new IllegalArgumentException("The argument '" + PARAM_PASSWORD + "' is required");
        }
        if (!(pwObj instanceof char[])) {
            throw new IllegalArgumentException(
                    "The argument '" + PARAM_PASSWORD + "' is expected to be of type 'char[]', but was: " + pwObj.getClass());
        }
        final char[] pw = (char[]) pwObj;
        final Object saltObj = params.get(PARAM_SALT);
        if (saltObj == null) {
            throw new IllegalArgumentException("The argument '" + PARAM_SALT + "' is required");
        }
        if (!(saltObj instanceof byte[])) {
            throw new IllegalArgumentException(
                    "The argument '" + PARAM_SALT + "' is expected to be of type 'byte[]', but was: " + saltObj.getClass());
        }
        final byte[] salt = (byte[]) saltObj;
        return new PwSalt(pw, salt);
    }

    private static final class PwSalt {

        private final char[] pw;

        private final byte[] salt;

        public PwSalt(char[] pw, byte[] salt) {
            super();
            this.pw = pw;
            this.salt = salt;
        }

        public char[] getPw() {
            return pw;
        }

        public byte[] getSalt() {
            return salt;
        }

    }

    /**
     * Combines secret key and IV.
     */
    private static final class Key {

        private final SecretKey secretKey;

        private final IvParameterSpec ivParameterSpec;

        /**
         * Constructor with mandatory data.
         * 
         * @param secretKey
         *            Secret key.
         * @param ivParameterSpec
         *            Initialization vector.
         */
        public Key(SecretKey secretKey, IvParameterSpec ivParameterSpec) {
            super();
            this.secretKey = secretKey;
            this.ivParameterSpec = ivParameterSpec;
        }

        public SecretKey getSecretKey() {
            return secretKey;
        }

        public IvParameterSpec getIvParameterSpec() {
            return ivParameterSpec;
        }

    }

}
