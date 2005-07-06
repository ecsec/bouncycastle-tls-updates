package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class KeyTransRecipientInformation
    extends RecipientInformation
{
    private KeyTransRecipientInfo   info;

    public KeyTransRecipientInformation(
        KeyTransRecipientInfo   info,
        EncryptedContentInfo    data)
    {
        super(AlgorithmIdentifier.getInstance(info.getKeyEncryptionAlgorithm()), data);
        
        this.info = info;
        this.rid = new RecipientId();

        RecipientIdentifier r = info.getRecipientIdentifier();

        try
        {
            if (r.isTagged())
            {
                ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

                rid.setSubjectKeyIdentifier(octs.getOctets());
            }
            else
            {
                IssuerAndSerialNumber   iAnds = IssuerAndSerialNumber.getInstance(r.getId());

                ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
                ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

                aOut.writeObject(iAnds.getName());

                rid.setIssuer(bOut.toByteArray());
                rid.setSerialNumber(iAnds.getSerialNumber().getValue());
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid rid in KeyTransRecipientInformation");
        }
    }

    /**
     * decrypt the content and return it as a byte array.
     */
    public byte[] getContent(
        Key      key,
        String   prov)
        throws CMSException, NoSuchProviderException
    {
        try
        {
            byte[]              encryptedKey = info.getEncryptedKey().getOctets();
            Cipher              keyCipher = Cipher.getInstance(keyEncAlg.getObjectId().getId(), prov);

            keyCipher.init(Cipher.DECRYPT_MODE, key);

            AlgorithmIdentifier aid = data.getContentEncryptionAlgorithm();
            String              alg = aid.getObjectId().getId();
            SecretKey           sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), alg);
            
            return getContentFromSessionKey(sKey, prov);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new CMSException("illegal blocksize in message.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (BadPaddingException e)
        {
            throw new CMSException("bad padding in message.", e);
        }
    }
}
