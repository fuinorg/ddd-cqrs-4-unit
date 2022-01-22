package org.fuin.dddcqrsunit;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
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

    private static final String ALGORITHM = "AES";

    private static final int KEY_SIZE = 256;

    private static final int GCM_IV_LENGTH = 12;

    private static final int GCM_TAG_LENGTH = 16;

    private static final String CIPHER_NAME = "AES/GCM/NoPadding";

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

    private int nextKey(final String keyId) {
        final Map<Integer, Key> keyVersions = keys.computeIfAbsent(keyId, k -> new HashMap<>());
        final int nextVersion = calculateNextVersion(keyVersions);
        keyVersions.computeIfAbsent(nextVersion, k -> new Key(createSecretKey(), createIvParameterSpec()));
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
        final byte[] ivBytes = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    private static SecretKey createSecretKey() {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            final SecretKey key = keyGenerator.generateKey();
            return new SecretKeySpec(key.getEncoded(), "AES");
        } catch (final NoSuchAlgorithmException ex) {
            throw new RuntimeException("Failed to create secret key", ex);
        }
    }

    @Override
    public boolean keyExists(@NotEmpty String keyId) {
        return keyIds.contains(keyId);
    }

    @Override
    public void createKey(@NotEmpty String keyId) throws DuplicateEncryptionKeyIdException {
        Utils4J.checkNotEmpty(keyId, keyId);
        if (keyIds.contains(keyId)) {
            throw new DuplicateEncryptionKeyIdException(keyId);
        }
        final String keyId1 = keyId;
        nextKey(keyId1);
        keyIds.add(keyId1);
    }

    @Override
    public String rotateKey(@NotEmpty String keyId) throws EncryptionKeyIdUnknownException {
        Utils4J.checkNotEmpty(keyId, keyId);
        if (!keyIds.contains(keyId)) {
            throw new EncryptionKeyIdUnknownException(keyId);
        }
        return "" + nextKey(keyId);
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
            final Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivParameterSpec.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
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
            final Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivParameterSpec.getIV());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            return cipher.doFinal(encryptedData.getEncryptedData());
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new DecryptionFailedException(ex);
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
