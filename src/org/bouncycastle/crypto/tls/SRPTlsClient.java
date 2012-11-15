package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Arrays;

public abstract class SRPTlsClient extends AbstractTlsClient
{
    public static final Integer EXT_SRP = new Integer(ExtensionType.srp);

    protected TlsCipherFactory cipherFactory;
    protected byte[] identity;
    protected byte[] password;

    public SRPTlsClient(byte[] identity, byte[] password, String fqdn)
    {
        this(new DefaultTlsCipherFactory(), identity, password, fqdn);
    }

    public SRPTlsClient(TlsCipherFactory cipherFactory, byte[] identity, byte[] password, String fqdn)
    {
        super(fqdn);
        this.cipherFactory = cipherFactory;
        this.identity = Arrays.clone(identity);
        this.password = Arrays.clone(password);
        
        // add SRP extension
        ByteArrayOutputStream srpData = new ByteArrayOutputStream();
        try {
			TlsUtils.writeOpaque8(this.identity, srpData);
		} catch (IOException e) {
			// should never happen
			e.printStackTrace();
		}
        this.addClientExtension(EXT_SRP, srpData.toByteArray());
    }

    public static int[] getDefaultCipherSuites(){
    	return new int[] {
                CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA, };
    }
    
    public int[] getCipherSuites()
    {
        return new int[] {
            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA, };
    }

    public void processServerExtensions(Hashtable serverExtensions)
    {
        // There is no server response for the SRP extension
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
                return createSRPKeyExchange(KeyExchangeAlgorithm.SRP);

            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
                return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_RSA);

            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_DSS);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCipher getCipher() throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm._3DES_EDE_CBC,
                    DigestAlgorithm.SHA);

            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_CBC,
                    DigestAlgorithm.SHA);

            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_CBC,
                    DigestAlgorithm.SHA);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsKeyExchange createSRPKeyExchange(int keyExchange)
    {
        return new TlsSRPKeyExchange(context, keyExchange, identity, password);
    }
}
