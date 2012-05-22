package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

public abstract class AbstractTlsClient implements TlsClient{

	protected TlsClientContext context;
	
	private Hashtable<Integer, byte[]> clientExtensions = new Hashtable<Integer, byte[]>();
	
	protected int selectedCipherSuite;
    protected int selectedCompressionMethod;
	private boolean secureRenegotiation;
	private final String fullyQualifiedDomainName;

    private byte[] sessionID;
	
	protected AbstractTlsClient(String fqdn){
		this.fullyQualifiedDomainName = fqdn;

		ByteArrayOutputStream serverList = new ByteArrayOutputStream();
		ByteArrayOutputStream sniData = new ByteArrayOutputStream();
		try {
			serverList.write(0x00);
			TlsUtils.writeOpaque16(fullyQualifiedDomainName.getBytes(), serverList);
			TlsUtils.writeOpaque16(serverList.toByteArray(), sniData);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.clientExtensions.put(new Integer(ExtensionType.server_name), sniData.toByteArray());

	}
	
	@Override
	public final void init(TlsClientContext context) {
		this.context = context;
	}

	public void addClientExtension(Integer i, byte[] b){
		clientExtensions.put(i, b);
	}
	
	public void removeClientExtension(Integer i){
		clientExtensions.remove(i);
	}
	
	@Override
	public final ProtocolVersion getClientVersion()
    {
        return ProtocolVersion.TLSv10;
    }

	@Override
	public final short[] getCompressionMethods() {
		  return new short[] { CompressionMethod.NULL };
	}

	@Override
	public final Hashtable<Integer, byte[]> getClientExtensions() throws IOException {
		return this.clientExtensions;
	}

	@Override
	public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        if (!ProtocolVersion.TLSv10.equals(serverVersion))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

	@Override
	public void notifySessionID(byte[] sessionID)
    {
       this.sessionID = sessionID;
    }

	@Override
	 public void notifySelectedCipherSuite(int selectedCipherSuite)
    {
        this.selectedCipherSuite = selectedCipherSuite;
    }
	    
	@Override
	public void notifySelectedCompressionMethod(short selectedCompressionMethod) {
		this.selectedCompressionMethod = selectedCompressionMethod;
	}

	@Override
	public void notifySecureRenegotiation(boolean secureNegotiation)
			throws IOException {
		this.secureRenegotiation = secureNegotiation;
		
	}

	@Override
	public void processServerExtensions(Hashtable serverExtensions) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public final TlsCompression getCompression() throws IOException
    {
        switch (selectedCompressionMethod)
        {
            case CompressionMethod.NULL:
                return new TlsNullCompression();

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected compression method was in the list of client-offered compression
                 * methods, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
	
	@Override
	public byte[] getSessionID() {
    	 return this.sessionID;
	}

	@Override
	public TlsClientContext getClientContext() {
    	 return this.context;
	}
}
