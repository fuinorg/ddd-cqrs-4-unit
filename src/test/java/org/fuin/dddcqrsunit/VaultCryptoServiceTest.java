package org.fuin.dddcqrsunit;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import org.fuin.ddd4j.ddd.EncryptedDataService;
import org.junit.jupiter.api.BeforeAll;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Test for the {@link VaultCryptoService} class.
 */
@Testcontainers
public final class VaultCryptoServiceTest extends AbstractCryptoServiceTest {

    private static final String TOKEN = UUID.randomUUID().toString();

    @SuppressWarnings("rawtypes")
    @Container
    private static VaultContainer vaultContainer = new VaultContainer<>(DockerImageName.parse("vault")).withVaultToken(TOKEN)
            .withInitCommand("secrets enable transit");

    private static String url;
    
    @BeforeAll
    final static void beforeClass() {
        url = "http://localhost:" + vaultContainer.getFirstMappedPort();
        System.out.println(url);
    }
    
    @Override
    protected Map<String, Object> getValidParams() {
        return Collections.emptyMap();
    }

    @Override
    protected EncryptedDataService createTestee() {
        return new VaultCryptoService(url, TOKEN);
    }

}
