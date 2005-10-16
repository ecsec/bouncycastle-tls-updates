package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class ElGamalTest
    implements Test
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    private BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
    private BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

    private BigInteger  g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger  p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

    public String getName()
    {
        return "ElGamal";
    }

    private TestResult testGP(
        int         size,
        BigInteger  g,
        BigInteger  p)
    {
        DHParameterSpec         elParams = new DHParameterSpec(p, g);

        try
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");

            keyGen.initialize(elParams);

            //
            // a side
            //
            KeyPair         keyPair = keyGen.generateKeyPair();
            SecureRandom    rand = new SecureRandom();
    
            Cipher  cipher = Cipher.getInstance("ElGamal", "BC");

            byte[]  in = "This is a test".getBytes();

            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), rand);

            byte[]  out = cipher.doFinal(in);

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), rand);

            out = cipher.doFinal(out);

            if (!arrayEquals(in, out))
            {
                return new SimpleTestResult(false, size + " bit 2-way test failed");
            }

            //
            // public key encoding test
            //
            byte[]                  pubEnc = keyPair.getPublic().getEncoded();
            KeyFactory              keyFac = KeyFactory.getInstance("ElGamal", "BC");
            X509EncodedKeySpec      pubX509 = new X509EncodedKeySpec(pubEnc);
            DHPublicKey             pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
            DHParameterSpec         spec = pubKey.getParams();

            if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit public key encoding/decoding test failed on parameters");
            }

            if (!((DHPublicKey)keyPair.getPublic()).getY().equals(pubKey.getY()))
            {
                return new SimpleTestResult(false, size + " bit public key encoding/decoding test failed on y value");
            }

            //
            // public key serialisation test
            //
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ObjectOutputStream      oOut = new ObjectOutputStream(bOut);

            oOut.writeObject(keyPair.getPublic());

            ByteArrayInputStream   bIn = new ByteArrayInputStream(bOut.toByteArray());
            ObjectInputStream      oIn = new ObjectInputStream(bIn);

            pubKey = (DHPublicKey)oIn.readObject();
            spec = pubKey.getParams();

            if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit public key serialisation test failed on parameters");
            }

            if (!((DHPublicKey)keyPair.getPublic()).getY().equals(pubKey.getY()))
            {
                return new SimpleTestResult(false, size + " bit public key serialisation test failed on y value");
            }

            //
            // private key encoding test
            //
            byte[]              privEnc = keyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
            DHPrivateKey        privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

            spec = privKey.getParams();

            if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit private key encoding/decoding test failed on parameters");
            }

            if (!((DHPrivateKey)keyPair.getPrivate()).getX().equals(privKey.getX()))
            {
                return new SimpleTestResult(false, size + " bit private key encoding/decoding test failed on y value");
            }

            //
            // private key serialisation test
            //
            bOut = new ByteArrayOutputStream();
            oOut = new ObjectOutputStream(bOut);

            oOut.writeObject(keyPair.getPrivate());

            bIn = new ByteArrayInputStream(bOut.toByteArray());
            oIn = new ObjectInputStream(bIn);

            privKey = (DHPrivateKey)oIn.readObject();
            spec = privKey.getParams();

            if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit private key serialisation test failed on parameters");
            }

            if (!((DHPrivateKey)keyPair.getPrivate()).getX().equals(privKey.getX()))
            {
                return new SimpleTestResult(false, size + " bit private key serialisation test failed on y value");
            }
        }
        catch (Exception e)
        {
                return new SimpleTestResult(false, size + " bit 2-way test failed - exception: " + e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    private TestResult testRandom(
        int         size)
    {
        try
        {
            AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
            a.init(size, new SecureRandom());
            AlgorithmParameters params = a.generateParameters();

            byte[] encodeParams = params.getEncoded();

            AlgorithmParameters a2 = AlgorithmParameters.getInstance("ElGamal", "BC");
            a2.init(encodeParams);

            // a and a2 should be equivalent!
            byte[] encodeParams_2 = a2.getEncoded();

            if (!arrayEquals(encodeParams, encodeParams_2))
            {
                return new SimpleTestResult(false, this.getName() + ": encode/decode parameters failed");
            }

            DHParameterSpec elP = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

            return testGP(size, elP.getG(), elP.getP());
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString());
        }
    }

    private boolean arrayEquals(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public TestResult perform()
    {
        TestResult      result;
  
        result = testGP(512, g512, p512);
        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = testGP(768, g768, p768);
        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = testGP(1024, g1024, p1024);
        if (!result.isSuccessful())
        {
            return result;
        }

        result = testRandom(256);
        if (!result.isSuccessful())
        {
            return result;
        }

        return result;
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        ElGamalTest         test = new ElGamalTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
