import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

public class SignTools {
	public static void main(String args[]) throws Exception{
		
		String keyurl = "./privatekey.key";
		
		Map<String, Object> params = new HashMap<String, Object>(); 
		
		params.put("subject", "YourSubject");
		params.put("body", "YourBod");
		
		Gson gson = new GsonBuilder().enableComplexMapKeySerialization().create();
		String query = gson.toJson(params);
		
		FileInputStream inputStream = new FileInputStream(keyurl);
		byte[] keyBytes = new byte[inputStream.available()];
		inputStream.read(keyBytes);
		inputStream.close();
		String keyString = new String(keyBytes, "UTF-8");
		
		String trimmedPrivateKey = keyString.replaceAll("(-+BEGIN (RSA )?PRIVATE KEY-+\\r?\\n|-+END (RSA )?PRIVATE KEY-+\\r?\\n?)", "");
		byte[] privateKeyBytes = Base64.decodeBase64(trimmedPrivateKey);
		DerInputStream derReader = new DerInputStream(privateKeyBytes);
		DerValue[] seq = derReader.getSequence(0);
		
		if (seq.length < 9) {
            System.out.println("Could not parse a PKCS1 private key.");
        }
		
		BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCoef = seq[8].getBigInteger();
        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(query.getBytes("UTF-8"));
        byte[] signBytes = signature.sign();
        System.out.println(Base64.encodeBase64String(signBytes).replaceAll("\n|\r", ""));
	}
}
