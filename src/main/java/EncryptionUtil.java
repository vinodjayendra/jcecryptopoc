
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.util.StringUtils;



public class EncryptionUtil {

	EncryptionUtil instance = null;
	private static String ALGORITHM_TYPE = "AES";
	private static String PADDING_SCHEME = "AES/CBC/PKCS5PADDING";
	private static String UNICODE_TYPE = "UTF-8";
	private static int KEY_CHARS_LENGTH = 16; // 128 bit key i.e 16 chars (16*8)
	private static String DIGEST_ALGORITHM = "SHA-1";
	private static String encryptionKey = "Bar12345Bar12345"; 
	private static String encryptionSalt = "RandomInitVector"; 

	public static String encrypt(String inputValue) {
		try {
			// Perform Encryption
			byte[] encrypted = getCipherInstanceByMode(Cipher.ENCRYPT_MODE).doFinal(inputValue.getBytes());
			System.out.println("encrypted string: " + Base64.encodeBase64String(encrypted));

			return Base64.encodeBase64String(encrypted);
		} catch (Exception encryptionException) {
			encryptionException.getMessage();
			encryptionException.printStackTrace();
		}

		return null;
	}

	public static String decrypt(String encryptedValue) {
		try {
			// Perform Decryption
			byte[] original = getCipherInstanceByMode(Cipher.DECRYPT_MODE).doFinal(Base64.decodeBase64(encryptedValue));
			return new String(original);
		} catch (Exception decryptionException) {
			decryptionException.getMessage();
			decryptionException.printStackTrace();
		}
		return null;
	}

	private static Cipher getCipherInstanceByMode(int mode) throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,Exception {

		// Generate Cipher
		Cipher cipher = Cipher.getInstance(PADDING_SCHEME);
		cipher.init(mode, new SecretKeySpec(generateSecureSecretKey(), ALGORITHM_TYPE), new IvParameterSpec(generateSecureSecretKey()));

		return cipher;
	}
	
	
	private static byte[] generateSecureSecretKey() throws UnsupportedEncodingException, NoSuchAlgorithmException, Exception   {
		//Perform Length Check for encryptionKey and encryptionSalt
		if(StringUtils.isEmpty(encryptionKey) || StringUtils.isEmpty(encryptionSalt)) {
			throw new Exception("EncryptionKey or EncryptionSalt is empty");
		}
		
		String concatenatedSecretKey = encryptionKey + encryptionSalt;
		if(concatenatedSecretKey.length() < KEY_CHARS_LENGTH) {
			throw new Exception("The minimum length of combined encryptionKey and encryptionSalt should be 16 chars");
		}
		
		byte[] key = concatenatedSecretKey.getBytes(UNICODE_TYPE);
		MessageDigest sha = MessageDigest.getInstance(DIGEST_ALGORITHM);
		key = sha.digest(key);
		key = Arrays.copyOf(key, KEY_CHARS_LENGTH); // use only first 128 bit i.e 16 chars (16*8)
		
		return key;
	}

	public static void main(String[] args) {
		System.out.println(decrypt(encrypt("Hello World")));
	}
}
