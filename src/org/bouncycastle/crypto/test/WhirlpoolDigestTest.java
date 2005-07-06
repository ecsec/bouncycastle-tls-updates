package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * ISO vector test for Whirlpool
 *  
 */
public class WhirlpoolDigestTest implements Test
{
    private static String[][] _isoVectors = 
    {
        {
            "",
            "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"
        },
        {
            "a",
            "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"
        },
        {
            "abc",
            "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5"
        },        
        {
            "message digest",
            "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E"
        },
        {
            "abcdefghijklmnopqrstuvwxyz",
            "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B"
        },
        {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467"
        },
        {
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB6014294D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B"
        },
        {
            "abcdbcdecdefdefgefghfghighijhijk",
            "2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C6916BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD"
        }        
    };
    
    private static String _millionAResultVector = "0C99005BEB57EFF50A7CF005560DDF5D29057FD86B20BFD62DECA0F1CCEA4AF51FC15490EDDC47AF32BB2B66C34FF9AD8C6008AD677F77126953B226E4ED8B01";
    
    public String getName()
    {
        return "Whirlpool";
    }

    public TestResult perform()
    {
        for (int i = 0; i < _isoVectors.length; i++)
        {
            TestResult result = performStandardVectorTest("ISO vector test ["+i+"]", _isoVectors[i][0],
                    _isoVectors[i][1]);
            if (!result.isSuccessful())
            {
                return result;
            }
        }

        byte[] millionAInByteArray = new byte[1000000];
        Arrays.fill(millionAInByteArray, (byte)'a');

        TestResult millionAsResult = performStandardVectorTest("Million 'a' test", 
                    millionAInByteArray, _millionAResultVector);
        if (!millionAsResult.isSuccessful())
        {
            return millionAsResult;
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }

    private TestResult performStandardVectorTest(String testTitle, byte[] inputBytes,
            String resultsAsHex)
    {
        return doPerformTest(testTitle, inputBytes, resultsAsHex);        
    }

    private TestResult doPerformTest(String testTitle, byte[] inputBytes, String resultsAsHex)
    {
        String resStr = createHexOutputFromDigest(inputBytes);
        if (!resultsAsHex.equals(resStr.toUpperCase()))
        {
            return SimpleTestResult.failed(SimpleTestResult.failedMessage("Whirlpool", testTitle,
                    resultsAsHex, resStr));
        }
        return SimpleTestResult.successful(testTitle + ": Okay");
    }

    private TestResult performStandardVectorTest(String testTitle, String inputBytesAsString,
            String resultsAsHex)
    {
        return doPerformTest(testTitle, inputBytesAsString.getBytes(), resultsAsHex);
    }

    private String createHexOutputFromDigest(byte[] digestBytes)
    {
        String resStr;
        Digest digest = new WhirlpoolDigest();
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.update(digestBytes, 0, digestBytes.length);
        digest.doFinal(resBuf, 0);
        resStr = new String(Hex.encode(resBuf));
        return resStr;
    }
    

    public static void main(String[] args)
    {
        WhirlpoolDigestTest test = new WhirlpoolDigestTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
