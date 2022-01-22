/*
 * Copyright (C) 2015 Michael Schnell. All rights reserved. 
 * http://www.fuin.org/
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see http://www.gnu.org/licenses/.
 */
package org.fuin.dddcqrsunit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.fuin.ddd4j.ddd.DecryptionFailedException;
import org.fuin.ddd4j.ddd.DuplicateEncryptionKeyIdException;
import org.fuin.ddd4j.ddd.EncryptedData;
import org.fuin.ddd4j.ddd.EncryptedDataService;
import org.fuin.ddd4j.ddd.EncryptionKeyIdUnknownException;
import org.fuin.ddd4j.ddd.EncryptionKeyVersionUnknownException;
import org.junit.jupiter.api.Test;

/**
 * Base test class for {@link EncryptedDataService} implementations.
 */
abstract class AbstractCryptoServiceTest {

    /**
     * Creates an instance of the implementation to test.
     * 
     * @return Newly created instance.
     */
    protected abstract EncryptedDataService createTestee();

    @Test
    final void testCreateKey() throws DuplicateEncryptionKeyIdException, EncryptionKeyIdUnknownException {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final EncryptedDataService testee = createTestee();

        // TEST
        testee.createKey(keyId);

        // VERIFY
        assertThat(testee.keyExists(keyId)).isTrue();
        assertThat(testee.getKeyVersion(keyId)).isEqualTo("1");

    }

    @Test
    final void testCreateKeyDuplicate() {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final EncryptedDataService testee = createTestee();
        try {
            testee.createKey(keyId);
        } catch (final DuplicateEncryptionKeyIdException ex) {
            throw new RuntimeException(ex);
        }

        // TEST
        try {
            testee.createKey(keyId);
            fail("Expected exception");
        } catch (final DuplicateEncryptionKeyIdException ex) {
            assertThat(ex.getMessage()).isEqualTo("Duplicate keyId: " + keyId);
        }

    }

    @Test
    final void testGetKeyVersionUnknown() throws DuplicateEncryptionKeyIdException {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final EncryptedDataService testee = createTestee();

        // TEST
        try {
            testee.getKeyVersion(keyId);
            fail("Expected exception");
        } catch (final EncryptionKeyIdUnknownException ex) {
            assertThat(ex.getMessage()).isEqualTo("Unknown keyId: " + keyId);
        }
    }

    @Test
    final void testRotateKey() throws DuplicateEncryptionKeyIdException, EncryptionKeyIdUnknownException {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final EncryptedDataService testee = createTestee();
        testee.createKey(keyId);
        assertThat(testee.keyExists(keyId)).isTrue();
        assertThat(testee.getKeyVersion(keyId)).isEqualTo("1");

        // TEST
        testee.rotateKey(keyId);

        // VERIFY
        assertThat(testee.getKeyVersion(keyId)).isEqualTo("2");

    }

    @Test
    final void testRotateKeyUnknown() {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final EncryptedDataService testee = createTestee();

        // TEST & VERIFY
        try {
            testee.rotateKey(keyId);
            fail("Expected exception");
        } catch (final EncryptionKeyIdUnknownException ex) {
            assertThat(ex.getMessage()).isEqualTo("Unknown keyId: " + keyId);
        }

    }

    @Test
    final void testEncryptDecrypt() throws EncryptionKeyIdUnknownException, DuplicateEncryptionKeyIdException,
            EncryptionKeyVersionUnknownException, DecryptionFailedException {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final EncryptedDataService testee = createTestee();
        testee.createKey(keyId);
        final String plainText = "Hello, world!";
        final String contentType = "text/plain";
        final String dataType = "MyText";

        // TEST
        final EncryptedData encryptedData = testee.encrypt(keyId, dataType, contentType, plainText.getBytes(StandardCharsets.UTF_8));

        // VERIFY
        assertThat(encryptedData.getKeyId()).isEqualTo(keyId);
        assertThat(encryptedData.getContentType()).isEqualTo(contentType);
        assertThat(encryptedData.getDataType()).isEqualTo(dataType);
        assertThat(encryptedData.getKeyVersion()).isEqualTo("1");
        assertThat(encryptedData.getEncryptedData()).isNotEmpty();

        // TEST
        final byte[] decryptedData = testee.decrypt(encryptedData);

        // VERIFY
        assertThat(new String(decryptedData)).isEqualTo(plainText);

    }

    @Test
    final void testEncryptUnknownKeyId()
            throws DuplicateEncryptionKeyIdException, EncryptionKeyVersionUnknownException, DecryptionFailedException {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final String plainText = "Hello, world!";
        final String contentType = "text/plain";
        final String dataType = "MyText";
        final EncryptedDataService testee = createTestee();

        // TEST
        try {
            testee.encrypt(keyId, dataType, contentType, plainText.getBytes(StandardCharsets.UTF_8));
            fail("Expected exception");
        } catch (final EncryptionKeyIdUnknownException ex) {
            assertThat(ex.getMessage()).isEqualTo("Unknown keyId: " + keyId);
        }

    }

    @Test
    final void testDecryptUnknownKeyId() throws DuplicateEncryptionKeyIdException, EncryptionKeyVersionUnknownException,
            DecryptionFailedException, EncryptionKeyIdUnknownException {

        // PREPARE
        final EncryptedDataService testee = createTestee();
        final EncryptedData encryptedData = new EncryptedData(UUID.randomUUID().toString(), "1", "MyData", "text/plain", new byte[] { 0 });

        // TEST
        try {
            testee.decrypt(encryptedData);
            fail("Expected exception");
        } catch (final EncryptionKeyIdUnknownException ex) {
            assertThat(ex.getMessage()).isEqualTo("Unknown keyId: " + encryptedData.getKeyId());
        }

    }

    @Test
    final void testDecryptUnknownVersion()
            throws EncryptionKeyIdUnknownException, DuplicateEncryptionKeyIdException, DecryptionFailedException {

        // PREPARE
        final String keyId = UUID.randomUUID().toString();
        final EncryptedDataService testee = createTestee();
        testee.createKey(keyId);
        final String plainText = "Hello, world!";
        final String contentType = "text/plain";
        final String dataType = "MyText";
        final EncryptedData encryptedData = testee.encrypt(keyId, dataType, contentType, plainText.getBytes(StandardCharsets.UTF_8));
        final EncryptedData wrongData = new EncryptedData(encryptedData.getKeyId(), "2", encryptedData.getDataType(),
                encryptedData.getContentType(), encryptedData.getEncryptedData());

        // TEST
        try {
            testee.decrypt(wrongData);
            fail("Expected exception");
        } catch (final EncryptionKeyVersionUnknownException ex) {
            assertThat(ex.getMessage()).isEqualTo("Unknown keyVersion: 2");
        }

    }

}
