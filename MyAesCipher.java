import java.util.Base64;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.security.spec.AlgorithmParameterSpec;
import java.lang.Exception;

public class MyAesCipher{
	static void myMethod() {
		//		encryptStrAndToBase64("26kozQaKwRuNJ24t", "result");
		try {
			String encrypted = encryptStrAndToBase64("26kozQaKwRuNJ24t", "Some text");
			String decrypted = decryptStrAndFromBase64("26kozQaKwRuNJ24t", encrypted);
			System.out.println(encrypted);
			System.out.println(decrypted);
		} catch (Exception e){
			System.out.println("Exception Error: " + e);
		}
	}

	public static void main(String[] args) {
		myMethod();
	}

	public static String encryptStrAndToBase64(String keyStr, String enStr) throws Exception{
		byte[] bytes = encrypt(keyStr, keyStr, enStr.getBytes("UTF-8"));
		return new String(Base64.getEncoder().encode(bytes), "UTF-8");
	}  

	public static String decryptStrAndFromBase64(String keyStr, String deStr) throws Exception{
		byte[] bytes = decrypt(keyStr, keyStr, Base64.getDecoder().decode(deStr.getBytes("UTF-8")));
		return new String(bytes, "UTF-8");
	}

	public static byte[] encrypt(String ivStr, String keyStr, byte[] bytes) throws Exception{
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(ivStr.getBytes());
		byte[] ivBytes = md.digest();

		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		sha.update(keyStr.getBytes());
		byte[] keyBytes = sha.digest();

		return encrypt(ivBytes, keyBytes, bytes);
	}

	static byte[] encrypt(byte[] ivBytes, byte[] keyBytes, byte[] bytes) throws Exception{
		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
		return cipher.doFinal(bytes);
	}

	public static byte[] decrypt(String ivStr, String keyStr, byte[] bytes) throws Exception{
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(ivStr.getBytes());
		byte[] ivBytes = md.digest();

		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		sha.update(keyStr.getBytes());
		byte[] keyBytes = sha.digest();

		return decrypt(ivBytes, keyBytes, bytes);
	}

	static byte[] decrypt(byte[] ivBytes, byte[] keyBytes, byte[] bytes)  throws Exception{
		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
		return cipher.doFinal(bytes);
	}
}
