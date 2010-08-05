package org.bouncycastle.cms.jcajce;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KEKRecipient;

public abstract class JceKEKRecipient
    implements KEKRecipient
{
    private Key recipientKey;
    protected EnvelopedDataHelper helper = new DefaultEnvelopedDataHelper();

    public JceKEKRecipient(Key recipientKey)
    {
        this.recipientKey = recipientKey;
    }

    public JceKEKRecipient setProvider(Provider provider)
    {
        this.helper = new ProviderEnvelopedDataHelper(provider);

        return this;
    }

    public JceKEKRecipient setProvider(String providerName)
    {
        this.helper = new NamedEnvelopedDataHelper(providerName);

        return this;
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        try
        {
            Cipher keyCipher = helper.createCipher(keyEncryptionAlgorithm.getAlgorithm());

            keyCipher.init(Cipher.UNWRAP_MODE, recipientKey);

            return keyCipher.unwrap(encryptedContentEncryptionKey, contentEncryptionAlgorithm.getAlgorithm().getId(), Cipher.SECRET_KEY);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
    }
}
