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

import java.util.HashMap;
import java.util.Map;

import org.fuin.ddd4j.ddd.DuplicateEncryptionKeyIdException;
import org.fuin.ddd4j.ddd.EncryptedDataService;
import org.fuin.ddd4j.ddd.EncryptionKeyIdUnknownException;
import org.junit.jupiter.api.Test;

/**
 * Test for the {@link InMemoryCryptoService} class.
 */
final class InMemoryCryptoServiceTest extends AbstractCryptoServiceTest {


    @Override
    protected Map<String, Object> getValidParams() {
        final Map<String, Object> params = new HashMap<>();
        params.put(InMemoryCryptoService.PARAM_PASSWORD, "abc".toCharArray());
        params.put(InMemoryCryptoService.PARAM_SALT, "123".getBytes());
        return params;
    }

    @Override
    protected EncryptedDataService createTestee() {
        return new InMemoryCryptoService();
    }
    
    @Test
    final void testCreateKeyNoParams() throws DuplicateEncryptionKeyIdException, EncryptionKeyIdUnknownException {

        // PREPARE
        final String keyId = "michael";
        final Map<String, Object> params = new HashMap<>();
        final InMemoryCryptoService testee = new InMemoryCryptoService();

        // TEST
        try {
            testee.createKey(keyId, params);
            fail("Expected exception");
        } catch (final IllegalArgumentException ex) {
            assertThat(ex.getMessage()).isEqualTo("The implementation requires parameters, but got none");
        }

    }

    
    @Test
    final void testCreateKeyWrongPasswordParam() throws DuplicateEncryptionKeyIdException, EncryptionKeyIdUnknownException {

        // PREPARE
        final String keyId = "michael";
        final Map<String, Object> params = new HashMap<>();
        final InMemoryCryptoService testee = new InMemoryCryptoService();

        // TEST
        try {
            params.put(InMemoryCryptoService.PARAM_PASSWORD, "abc");
            params.put(InMemoryCryptoService.PARAM_SALT, "123".getBytes());
            testee.createKey(keyId, params);
            fail("Expected exception");
        } catch (final IllegalArgumentException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo("The argument 'password' is expected to be of type 'char[]', but was: class java.lang.String");
        }
    }

    @Test
    final void testCreateKeyWrongSaltParam() throws DuplicateEncryptionKeyIdException, EncryptionKeyIdUnknownException {

        // PREPARE
        final String keyId = "michael";
        final Map<String, Object> params = new HashMap<>();
        final InMemoryCryptoService testee = new InMemoryCryptoService();
        params.put(InMemoryCryptoService.PARAM_PASSWORD, "abc".toCharArray());
        params.put(InMemoryCryptoService.PARAM_SALT, "123");

        // TEST
        try {
            testee.createKey(keyId, params);
            fail("Expected exception");
        } catch (final IllegalArgumentException ex) {
            assertThat(ex.getMessage())
                    .isEqualTo("The argument 'salt' is expected to be of type 'byte[]', but was: class java.lang.String");
        }

    }

    @Test
    final void testCreateKeyNoPasswordParam() throws DuplicateEncryptionKeyIdException, EncryptionKeyIdUnknownException {

        // PREPARE
        final String keyId = "michael";
        final Map<String, Object> params = new HashMap<>();
        final InMemoryCryptoService testee = new InMemoryCryptoService();

        // TEST
        try {
            params.put(InMemoryCryptoService.PARAM_SALT, "123".getBytes());
            testee.createKey(keyId, params);
            fail("Expected exception");
        } catch (final IllegalArgumentException ex) {
            assertThat(ex.getMessage()).isEqualTo("The argument 'password' is required");
        }
    }

    @Test
    final void testCreateKeyNoSaltParam() throws DuplicateEncryptionKeyIdException, EncryptionKeyIdUnknownException {

        // PREPARE
        final String keyId = "michael";
        final Map<String, Object> params = new HashMap<>();
        final InMemoryCryptoService testee = new InMemoryCryptoService();
        params.put(InMemoryCryptoService.PARAM_PASSWORD, "abc".toCharArray());

        // TEST
        try {
            testee.createKey(keyId, params);
            fail("Expected exception");
        } catch (final IllegalArgumentException ex) {
            assertThat(ex.getMessage()).isEqualTo("The argument 'salt' is required");
        }

    }

}
