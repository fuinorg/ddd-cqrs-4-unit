package org.fuin.dddcqrsunit;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.fuin.ddd4j.ddd.DecryptionFailedException;
import org.fuin.ddd4j.ddd.DuplicateEncryptionKeyIdException;
import org.fuin.ddd4j.ddd.EncryptedData;
import org.fuin.ddd4j.ddd.EncryptedDataService;
import org.fuin.ddd4j.ddd.EncryptionKeyIdUnknownException;
import org.fuin.ddd4j.ddd.EncryptionKeyVersionUnknownException;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;

public class VaultCryptoService implements EncryptedDataService {

    private final Vault vault;

    public VaultCryptoService(final String url, final String token) {
        super();
        try {
            vault = new Vault(new VaultConfig().address(url).engineVersion(1).token(token).build());
        } catch (final VaultException ex) {
            throw new RuntimeException("Failed to create connection to vault engine", ex);
        }
    }

    @Override
    public EncryptedData encrypt(@NotEmpty String keyId, @NotEmpty String dataType, @NotEmpty String contentType, @NotEmpty byte[] data)
            throws EncryptionKeyIdUnknownException {

        // Needed to throw an exception in case of an non-existing key
        // Vault creates otherwise automatically a key when there is none
        getKeyVersion(keyId);

        try {
            final String plainDataBase64 = Base64.getEncoder().encodeToString(data);
            final LogicalResponse response = vault.logical().write("transit/encrypt/" + keyId,
                    Collections.singletonMap("plaintext", plainDataBase64));
            if (response.getRestResponse().getStatus() != 200) {
                throw new RuntimeException("Encryption failed with code: " + response.getRestResponse().getStatus());
            }
            final String cipherText = response.getDataObject().getString("ciphertext");
            final int p = cipherText.lastIndexOf(':');
            if (p < 8) {
                throw new RuntimeException("Failed to extract header: '" + cipherText + "'");
            }
            final String withoutHeader = cipherText.substring(p + 1);
            final Integer keyVersion = response.getDataObject().getInt("key_version");
            final byte[] encryptedData = Base64.getDecoder().decode(withoutHeader.getBytes(StandardCharsets.US_ASCII));
            return new EncryptedData(keyId, "" + keyVersion, dataType, contentType, encryptedData);
        } catch (final VaultException ex) {
            throw new RuntimeException("Encryption failed", ex);
        }

    }

    @Override
    public @NotEmpty byte[] decrypt(@NotNull EncryptedData encryptedData)
            throws EncryptionKeyIdUnknownException, EncryptionKeyVersionUnknownException, DecryptionFailedException {

        // Needed to throw an exception in case of an non-existing key
        // Otherwise we have no way to know if the key or the version does not exist
        getKeyVersion(encryptedData.getKeyId());

        try {
            final String cipherText = "vault:v" + encryptedData.getKeyVersion() + ":"
                    + Base64.getEncoder().encodeToString(encryptedData.getEncryptedData());
            final LogicalResponse response = vault.logical().write("transit/decrypt/" + encryptedData.getKeyId(),
                    Collections.singletonMap("ciphertext", cipherText));
            if (response.getRestResponse().getStatus() == 400) {
                throw new EncryptionKeyVersionUnknownException(encryptedData.getKeyVersion());
            }
            if (response.getRestResponse().getStatus() != 200) {
                throw new RuntimeException("Decryption failed with code: " + response.getRestResponse().getStatus());
            }
            return Base64.getDecoder().decode(response.getDataObject().getString("plaintext"));
        } catch (final VaultException ex) {
            throw new RuntimeException("Encryption failed", ex);
        }
    }

    @Override
    public boolean keyExists(@NotEmpty String keyId) {
        try {
            final LogicalResponse response = vault.logical().read("transit/keys/" + keyId);
            if (response.getRestResponse().getStatus() == 404) {
                return false;
            }
            if (response.getRestResponse().getStatus() != 200) {
                throw new RuntimeException("KeyExists failed with code: " + response.getRestResponse().getStatus());
            }
            return true;
        } catch (final VaultException ex) {
            throw new RuntimeException("KeyExists failed", ex);
        }
    }

    @Override
    public void createKey(@NotEmpty String keyId) throws DuplicateEncryptionKeyIdException {
        if (keyExists(keyId)) {
            throw new DuplicateEncryptionKeyIdException(keyId);
        }
        try {
            final LogicalResponse response = vault.logical().write("transit/keys/" + keyId, new HashMap<>());
            if (response.getRestResponse().getStatus() != 204) {
                throw new RuntimeException("CreateKey failed with code: " + response.getRestResponse().getStatus());
            }
        } catch (final VaultException ex) {
            throw new RuntimeException("CreateKey failed", ex);
        }
    }

    @Override
    public String rotateKey(@NotEmpty String keyId) throws EncryptionKeyIdUnknownException {
        try {
            final LogicalResponse response = vault.logical().write("transit/keys/" + keyId + "/rotate", new HashMap<>());
            if (response.getRestResponse().getStatus() == 400) {
                throw new EncryptionKeyIdUnknownException(keyId);
            }
            if (response.getRestResponse().getStatus() != 204) {
                throw new RuntimeException("RotateKey failed with code: " + response.getRestResponse().getStatus());
            }
            return getKeyVersion(keyId);
        } catch (final VaultException ex) {
            throw new RuntimeException("RotateKey failed", ex);
        }
    }

    @Override
    public String getKeyVersion(@NotEmpty String keyId) throws EncryptionKeyIdUnknownException {
        try {
            final LogicalResponse response = vault.logical().read("transit/keys/" + keyId);
            if (response.getRestResponse().getStatus() == 404) {
                throw new EncryptionKeyIdUnknownException(keyId);
            }
            if (response.getRestResponse().getStatus() != 200) {
                throw new RuntimeException("getKeyVersion failed with code: " + response.getRestResponse().getStatus());
            }
            return "" + response.getDataObject().getInt("latest_version");
        } catch (final VaultException ex) {
            throw new RuntimeException("getKeyVersion failed", ex);
        }
    }

}
