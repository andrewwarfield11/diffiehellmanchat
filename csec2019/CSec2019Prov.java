
package csec2019;

import java.security.Provider;

/**
 * A Provider that links the AES cipher from Project 1 into the JCE
 */
public class CSec2019Prov extends Provider {
    /**
     * Constructor.
     *
     * Use this with java.security.Security.insertProviderAt() to install this
     * provider into your Chat project.
     */
    public CSec2019Prov() {
        super("CSec2019", 1.0, "Provider for AES from Project 1.");

        put("Cipher.AES", "csec2019.AESCipher");
    }
}
