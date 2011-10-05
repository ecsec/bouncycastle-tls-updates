package org.bouncycastle.asn1;

public class ASN1ObjectIdentifier
    extends DERObjectIdentifier
{
    public ASN1ObjectIdentifier(String identifier)
    {
        super(identifier);
    }

    ASN1ObjectIdentifier(byte[] bytes)
    {
        super(bytes);
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return
     */
    public ASN1ObjectIdentifier branch(String branchID)
    {
        return new ASN1ObjectIdentifier(getId() + "." + branchID);
    }

    /**
     * Return  true if this oid is an extension of the passed in branch, stem.
     * @param stem the arc or branch that is a possible parent.
     * @return  true if the branch is on the passed in stem, false otherwise.
     */
    public boolean on(ASN1ObjectIdentifier stem)
    {
        String id = getId(), stemId = stem.getId();
        return id.length() > stemId.length() && id.charAt(stemId.length()) == '.' && id.startsWith(stemId);
    }
}
