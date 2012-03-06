
package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <code>NoticeReference</code> class, used in
 * <code>CertificatePolicies</code> X509 V3 extensions
 * (in policy qualifiers).
 * 
 * <pre>
 *  NoticeReference ::= SEQUENCE {
 *      organization     DisplayText,
 *      noticeNumbers    SEQUENCE OF INTEGER }
 *
 * </pre> 
 * 
 * @see PolicyQualifierInfo
 * @see PolicyInformation
 */
public class NoticeReference 
    extends ASN1Object
{
   private DisplayText organization;
   private ASN1Sequence noticeNumbers;

   /**
    * Creates a new <code>NoticeReference</code> instance.
    *
    * @param orgName a <code>String</code> value
    * @param numbers a <code>Vector</code> value
    */
   public NoticeReference(
       String orgName,
       Vector numbers) 
   {
      organization = new DisplayText(orgName);

      Object o = numbers.elementAt(0);

      ASN1EncodableVector av = new ASN1EncodableVector();
      if (o instanceof Integer)
      {
         Enumeration it = numbers.elements();

         while (it.hasMoreElements())
         {
            Integer nm = (Integer) it.nextElement();
               ASN1Integer di = new ASN1Integer(nm.intValue());
            av.add (di);
         }
      }

      noticeNumbers = new DERSequence(av);
   }

   /**
    * Creates a new <code>NoticeReference</code> instance.
    *
    * @param orgName a <code>String</code> value
    * @param numbers an <code>ASN1EncodableVector</code> value
    */
   public NoticeReference(
       String orgName, 
       ASN1Sequence numbers) 
   {
       organization = new DisplayText (orgName);
       noticeNumbers = numbers;
   }

   /**
    * Creates a new <code>NoticeReference</code> instance.
    *
    * @param displayTextType an <code>int</code> value
    * @param orgName a <code>String</code> value
    * @param numbers an <code>ASN1EncodableVector</code> value
    */
   public NoticeReference(
       int displayTextType,
       String orgName,
       ASN1Sequence numbers) 
   {
       organization = new DisplayText(displayTextType, 
                                     orgName);
       noticeNumbers = numbers;
   }

   /**
    * Creates a new <code>NoticeReference</code> instance.
    * <p>Useful for reconstructing a <code>NoticeReference</code>
    * instance from its encodable/encoded form. 
    *
    * @param as an <code>ASN1Sequence</code> value obtained from either
    * calling @{link toASN1Primitive()} for a <code>NoticeReference</code>
    * instance or from parsing it from a DER-encoded stream. 
    */
   public NoticeReference(
       ASN1Sequence as) 
   {
       if (as.size() != 2)
       {
            throw new IllegalArgumentException("Bad sequence size: "
                    + as.size());
       }

       organization = DisplayText.getInstance(as.getObjectAt(0));
       noticeNumbers = ASN1Sequence.getInstance(as.getObjectAt(1));
   }

   public static NoticeReference getInstance(
       Object as) 
   {
      if (as instanceof NoticeReference)
      {
          return (NoticeReference)as;
      }
      else if (as != null)
      {
          return new NoticeReference(ASN1Sequence.getInstance(as));
      }

      return null;
   }
   
   public DisplayText getOrganization()
   {
       return organization;
   }
   
   public ASN1Sequence getNoticeNumbers()
   {
       return noticeNumbers;
   }
   
   /**
    * Describe <code>toASN1Object</code> method here.
    *
    * @return a <code>ASN1Primitive</code> value
    */
   public ASN1Primitive toASN1Primitive()
   {
      ASN1EncodableVector av = new ASN1EncodableVector();
      av.add (organization);
      av.add (noticeNumbers);
      return new DERSequence (av);
   }
}
