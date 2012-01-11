package org.bouncycastle.cert;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;

/**
 * Holding class for an X.509 CRL Entry structure.
 */
public class X509CRLEntryHolder
{
    private TBSCertList.CRLEntry entry;

    X509CRLEntryHolder(TBSCertList.CRLEntry entry)
    {
        this.entry = entry;
    }

    /**
     * Return the serial number of the certificate associated with this CRLEntry.
     *
     * @return the revoked certificate's serial number.
     */
    public BigInteger getSerialNumber()
    {
        return entry.getUserCertificate().getValue();
    }

    /**
     * Return the date on which the certificate associated with this CRLEntry was revoked.
     *
     * @return the revocation date for the revoked certificate.
     */
    public Date getRevocationDate()
    {
        return entry.getRevocationDate().getDate();
    }

    /**
     * Return whether or not the holder's CRL entry contains extensions.
     *
     * @return true if extension are present, false otherwise.
     */
    public boolean hasExtensions()
    {
        return entry.hasExtensions();
    }

    /**
     * Look up the extension associated with the passed in OID.
     *
     * @param oid the OID of the extension of interest.
     *
     * @return the extension if present, null otherwise.
     */
    public X509Extension getExtension(ASN1ObjectIdentifier oid)
    {
        X509Extensions extensions = entry.getExtensions();

        if (extensions != null)
        {
            return extensions.getExtension(oid);
        }

        return null;
    }

    /**
     * Returns a list of ASN1ObjectIdentifier objects representing the OIDs of the
     * extensions contained in this holder's CRL entry.
     *
     * @return a list of extension OIDs.
     */
    public List getExtensionOIDs()
    {
        return CertUtils.getExtensionOIDs(entry.getExtensions());
    }

    /**
     * Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
     * critical extensions contained in this holder's CRL entry.
     *
     * @return a set of critical extension OIDs.
     */
    public Set getCriticalExtensionOIDs()
    {
        return CertUtils.getCriticalExtensionOIDs(entry.getExtensions());
    }

    /**
     * Returns a set of ASN1ObjectIdentifier objects representing the OIDs of the
     * non-critical extensions contained in this holder's CRL entry.
     *
     * @return a set of non-critical extension OIDs.
     */
    public Set getNonCriticalExtensionOIDs()
    {
        return CertUtils.getNonCriticalExtensionOIDs(entry.getExtensions());
    }
}
