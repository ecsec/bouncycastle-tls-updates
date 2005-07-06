package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * basic test class for key generation for a DES-EDE block cipher, basically
 * this just exercises the provider, and makes sure we are behaving sensibly,
 * correctness of the implementation is shown in the lightweight test classes.
 */
public class DESedeTest
    implements Test
{
    static String[] cipherTests1 =
    {
        "112",
        "2f4bc6b30c893fa549d82c560d61cf3eb088aed020603de249d82c560d61cf3e529e95ecd8e05394",
        "128",
        "2f4bc6b30c893fa549d82c560d61cf3eb088aed020603de249d82c560d61cf3e529e95ecd8e05394",
        "168",
        "50ddb583a25c21e6c9233f8e57a86d40bb034af421c03096c9233f8e57a86d402fce91e8eb639f89",
        "192",
        "50ddb583a25c21e6c9233f8e57a86d40bb034af421c03096c9233f8e57a86d402fce91e8eb639f89",
    };

    static byte[]   input1 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");
    static byte[]   input2 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c");

    static RC2ParameterSpec rc2Spec = new RC2ParameterSpec(128, Hex.decode("0123456789abcdef"));
    static RC5ParameterSpec rc5Spec = new RC5ParameterSpec(16, 16, 32, Hex.decode("0123456789abcdef"));

    /**
     * a fake random number generator - we just want to make sure the random numbers
     * aren't random so that we get the same output, while still getting to test the
     * key generation facilities.
     */
    private class FixedSecureRandom
        extends SecureRandom
    {
        byte[]  seed = {
                (byte)0xaa, (byte)0xfd, (byte)0x12, (byte)0xf6, (byte)0x59,
                (byte)0xca, (byte)0xe6, (byte)0x34, (byte)0x89, (byte)0xb4,
                (byte)0x79, (byte)0xe5, (byte)0x07, (byte)0x6d, (byte)0xde,
                (byte)0xc2, (byte)0xf0, (byte)0x6c, (byte)0xb5, (byte)0x8f
        };

        public void nextBytes(
            byte[]  bytes)
        {
            int offset = 0;

            while ((offset + seed.length) < bytes.length)
            {
                System.arraycopy(seed, 0, bytes, offset, seed.length);
                offset += seed.length;
            }

            System.arraycopy(seed, 0, bytes, offset, bytes.length - offset);
        }
    }

    public String getName()
    {
        return "DESEDE";
    }

    private boolean equalArray(
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

    private boolean equalArray(
        byte[]  a,
        byte[]  b,
        int     length)
    {
        if (a.length < length)
        {
            return false;
        }

        if (b.length < length)
        {
            return false;
        }

        for (int i = 0; i != length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    private TestResult wrapTest(
        int     id,
        byte[]  kek,
        byte[]  iv,
        byte[]  in,
        byte[]  out)
    {
        try
        {
            Cipher wrapper = Cipher.getInstance("DESedeWrap", "BC");

            wrapper.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "DESEDE"), new IvParameterSpec(iv));

            try
            {
                byte[]  cText = wrapper.wrap(new SecretKeySpec(in, "DESEDE"));
                if (!equalArray(cText, out))
                {
                    return new SimpleTestResult(false, getName() + ": failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
                return new SimpleTestResult(false, getName() + ": failed wrap test exception " + e.toString());
            }

            wrapper.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "DESEDE"));

            try
            {
                Key  pText = wrapper.unwrap(out, "DESede", Cipher.SECRET_KEY);
                if (!equalArray(pText.getEncoded(), in))
                {
                    return new SimpleTestResult(false, getName() + ": failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText.getEncoded())));
                }
            }
            catch (Exception e)
            {
                return new SimpleTestResult(false, getName() + ": failed unwrap test exception " + e.toString());
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            return new SimpleTestResult(false, getName() + ": failed exception " + ex.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public TestResult test(
        int         strength,
        byte[]      input,
        byte[]      output)
    {
        Key                     key;
        KeyGenerator            keyGen;
        SecureRandom            rand;
        Cipher                  in, out;
        CipherInputStream       cIn;
        CipherOutputStream      cOut;
        ByteArrayInputStream    bIn;
        ByteArrayOutputStream   bOut;

        rand = new FixedSecureRandom();

        try
        {
            keyGen = KeyGenerator.getInstance("DESEDE", "BC");
            keyGen.init(strength, rand);

            key = keyGen.generateKey();

            in = Cipher.getInstance("DESEDE/ECB/PKCS7Padding", "BC");
            out = Cipher.getInstance("DESEDE/ECB/PKCS7Padding", "BC");

            out.init(Cipher.ENCRYPT_MODE, key, rand);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": DESEDE failed initialisation - " + e.toString());
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": DESEDE failed initialisation - " + e.toString());
        }

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        try
        {
            for (int i = 0; i != input.length / 2; i++)
            {
                cOut.write(input[i]);
            }
            cOut.write(input, input.length / 2, input.length - input.length / 2);
            cOut.close();
        }
        catch (IOException e)
        {
            return new SimpleTestResult(false, getName() + ": DESEDE failed encryption - " + e.toString());
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!equalArray(bytes, output))
        {
            return new SimpleTestResult(false, getName() + ": DESEDE failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        try
        {
            DataInputStream dIn = new DataInputStream(cIn);

            bytes = new byte[input.length];

            for (int i = 0; i != input.length / 2; i++)
            {
                bytes[i] = (byte)dIn.read();
            }
            dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": DESEDE failed encryption - " + e.toString());
        }

        if (!equalArray(bytes, input))
        {
            return new SimpleTestResult(false, getName() + ": DESEDE failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // keyspec test
        //
        try
        {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede", "BC");
            DESedeKeySpec keySpec = (DESedeKeySpec)keyFactory.getKeySpec((SecretKey)key, DESedeKeySpec.class);

            if (!equalArray(key.getEncoded(), keySpec.getKey(), 16))
            {
                return new SimpleTestResult(false, getName() + ": DESEDE KeySpec does not match key.");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": DESEDE failed keyspec - " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": DESEDE Okay");
    }

    public TestResult perform()
    {
        TestResult  result;

        for (int i = 0; i != cipherTests1.length; i += 2)
        {
            result = test(Integer.parseInt(cipherTests1[i]), input1, Hex.decode(cipherTests1[i + 1]));
            if (!result.isSuccessful())
            {
                return result;
            }
        }

        byte[]  kek1 = Hex.decode("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f");
        byte[]  iv1 = Hex.decode("5dd4cbfc96f5453b");
        byte[]  in1 = Hex.decode("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98");
        byte[]  out1 = Hex.decode("690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4");

        result = wrapTest(1, kek1, iv1, in1, out1);
        if (!result.isSuccessful())
        {
            return result;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new DESedeTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
