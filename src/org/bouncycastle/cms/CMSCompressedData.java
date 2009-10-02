package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.InflaterInputStream;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.util.io.StreamOverflowException;

/**
 * containing class for an CMS Compressed Data object
 */
public class CMSCompressedData
{
    ContentInfo                 contentInfo;

    public CMSCompressedData(
        byte[]    compressedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSCompressedData(
        InputStream    compressedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSCompressedData(
        ContentInfo contentInfo)
        throws CMSException
    {
        this.contentInfo = contentInfo;
    }

    /**
     * Return the uncompressed content.
     *
     * @return the uncompressed content
     * @throws CMSException if there is an exception uncompressing the data.
     */
    public byte[] getContent()
        throws CMSException
    {
        CompressedData  comData = CompressedData.getInstance(contentInfo.getContent());
        ContentInfo     content = comData.getEncapContentInfo();

        ASN1OctetString bytes = (ASN1OctetString)content.getContent();

        InflaterInputStream     zIn = new InflaterInputStream(bytes.getOctetStream());

        try
        {
            return CMSUtils.streamToByteArray(zIn);
        }
        catch (IOException e)
        {
            throw new CMSException("exception reading compressed stream.", e);
        }
    }

    /**
     * Return the uncompressed content, throwing an exception if the data size
     * is greater than the passed in limit.
     *
     * @param limit maximum number of bytes to read
     * @return the content read
     * @throws CMSException if there is an exception uncompressing the data.
     * @throws StreamOverflowException if the limit is reached and data is still available.
     */
    public byte[] getContent(int limit)
        throws CMSException
    {
        CompressedData  comData = CompressedData.getInstance(contentInfo.getContent());
        ContentInfo     content = comData.getEncapContentInfo();

        ASN1OctetString bytes = (ASN1OctetString)content.getContent();

        InflaterInputStream     zIn = new InflaterInputStream(bytes.getOctetStream());

        try
        {
            return CMSUtils.streamToByteArray(zIn, limit);
        }
        catch (IOException e)
        {
            throw new CMSException("exception reading compressed stream.", e);
        }
    }

    /**
     * return the ContentInfo 
     */
    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }
    
    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
}
