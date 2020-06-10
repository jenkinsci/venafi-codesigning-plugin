package io.jenkins.plugins.venaficodesigning;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

public class WindowsRegistryTest {
    private MockCommandLauncher launcher;
    private WindowsRegistry registry;

    @Before
    public void setUp() {
        launcher = new MockCommandLauncher();
        registry = new WindowsRegistry(launcher, true);
    }

    @Test
    public void testParseReadKeyOutput() throws Exception {
        launcher.setOutput(
            "\n"
            + "        HKEY_LOCAL_MACHINE\\Software\\Venafi\\Platform\n"
            + "        Client Base Path    REG_SZ    C:\\Program Files\\Venafi\\\n"
            + "\n\n"
        );
        launcher.setCode(0);

        String result = registry.readKey("HKEY_LOCAL_MACHINE\\Software\\Venafi\\Platform",
            "Client Base Path");
        assertEquals("C:\\Program Files\\Venafi\\", result);
    }

    @Test
    public void testReadKey_KeyNotFound() throws Exception {
        launcher.setOutput("ERROR: The system was unable to find the specified registry key or value.\n");
        launcher.setCode(1);
        assertNull(registry.readKey("HKEY_LOCAL_MACHINE\\Software\\Venafi\\Platform",
            "Client Base Path"));
    }

    @Test
    public void testReadKeyError() throws Exception {
        launcher.setOutput("ERROR: Unknown error.\n");
        launcher.setCode(1);
        try {
            registry.readKey("HKEY_LOCAL_MACHINE\\Software\\Venafi\\Platform",
                "Client Base Path");
            fail("IOException expected");
        } catch (IOException e) {
            // Success.
        }
    }
}
