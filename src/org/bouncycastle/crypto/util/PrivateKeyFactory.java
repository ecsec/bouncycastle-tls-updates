package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
 */
public class PrivateKeyFactory
{
    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
     * 
     * @param privateKeyInfoData the PrivateKeyInfo encoding
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData) throws IOException
    {
        return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
    }

    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a
     * stream.
     * 
     * @param inStr the stream to read the PrivateKeyInfo encoding from
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr) throws IOException
    {
        return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
     * 
     * @param keyInfo the PrivateKeyInfo object containing the key material
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo) throws IOException
    {
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();

        if (algId.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption))
        {
            RSAPrivateKey keyStructure = RSAPrivateKey.getInstance(
                keyInfo.parsePrivateKey());

            return new RSAPrivateCrtKeyParameters(keyStructure.getModulus(),
                keyStructure.getPublicExponent(), keyStructure.getPrivateExponent(),
                keyStructure.getPrime1(), keyStructure.getPrime2(), keyStructure.getExponent1(),
                keyStructure.getExponent2(), keyStructure.getCoefficient());
        }
        // TODO?
//      else if (algId.getObjectId().equals(X9ObjectIdentifiers.dhpublicnumber))
        else if (algId.getAlgorithm().equals(PKCSObjectIdentifiers.dhKeyAgreement))
        {
            DHParameter params = DHParameter.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            DERInteger derX = (DERInteger)keyInfo.parsePrivateKey();

            BigInteger lVal = params.getL();
            int l = lVal == null ? 0 : lVal.intValue();
            DHParameters dhParams = new DHParameters(params.getP(), params.getG(), null, l);

            return new DHPrivateKeyParameters(derX.getValue(), dhParams);
        }
        else if (algId.getAlgorithm().equals(OIWObjectIdentifiers.elGamalAlgorithm))
        {
            ElGamalParameter params = new ElGamalParameter(
                (ASN1Sequence)keyInfo.getPrivateKeyAlgorithm().getParameters());
            DERInteger derX = (DERInteger)keyInfo.parsePrivateKey();

            return new ElGamalPrivateKeyParameters(derX.getValue(), new ElGamalParameters(
                params.getP(), params.getG()));
        }
        else if (algId.getAlgorithm().equals(X9ObjectIdentifiers.id_dsa))
        {
            DERInteger derX = (DERInteger)keyInfo.parsePrivateKey();
            ASN1Encodable de = keyInfo.getPrivateKeyAlgorithm().getParameters();

            DSAParameters parameters = null;
            if (de != null)
            {
                DSAParameter params = DSAParameter.getInstance(de.toASN1Primitive());
                parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
            }

            return new DSAPrivateKeyParameters(derX.getValue(), parameters);
        }
        else if (algId.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            X962Parameters params = new X962Parameters(
                (ASN1Primitive)keyInfo.getPrivateKeyAlgorithm().getParameters());
            ECDomainParameters dParams = null;

            if (params.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
                X9ECParameters ecP = X962NamedCurves.getByOID(oid);

                if (ecP == null)
                {
                    ecP = SECNamedCurves.getByOID(oid);

                    if (ecP == null)
                    {
                        ecP = NISTNamedCurves.getByOID(oid);

                        if (ecP == null)
                        {
                            ecP = TeleTrusTNamedCurves.getByOID(oid);
                        }
                    }
                }

                dParams = new ECDomainParameters(ecP.getCurve(), ecP.getG(), ecP.getN(),
                    ecP.getH(), ecP.getSeed());
            }
            else
            {
                X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());
                dParams = new ECDomainParameters(ecP.getCurve(), ecP.getG(), ecP.getN(),
                    ecP.getH(), ecP.getSeed());
            }

            ECPrivateKeyStructure ec = new ECPrivateKeyStructure(
                (ASN1Sequence)keyInfo.parsePrivateKey());

            return new ECPrivateKeyParameters(ec.getKey(), dParams);
        }
        else
        {
            throw new RuntimeException("algorithm identifier in key not recognised");
        }
    }
}
