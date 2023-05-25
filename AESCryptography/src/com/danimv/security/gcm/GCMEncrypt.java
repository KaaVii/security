/**
 * @author dan
 */

package com.danimv.security.gcm;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

public class GCMEncrypt {
	private static final Logger logger = Logger.getLogger(GCMEncrypt.class.toString());;
	// AES-GCM parameters
	public static final int AES_KEY_SIZE = 128; // in bits
	public static final int GCM_NONCE_LENGTH = 12; // in bytes
	public static final int GCM_TAG_LENGTH = 16; // in bytes

	public static void main(String[] args) throws Exception {

		int testNum = 0; // pass

		if (args.length > 0) {
			testNum = Integer.parseInt(args[0]);
			if (testNum < 0 || testNum > 3) {
				logger.info("Usage: java AESGCMUpdateAAD2 [X]");
				logger.info("X can be 0, 1, 2, 3");
				System.exit(1);
			}
		}
		byte[] input = "You can't always get what you want, But if you try sometimes well you might find, You get what you need"
				.getBytes();

		// Initialise random and generate key
		SecureRandom random = SecureRandom.getInstanceStrong();
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(AES_KEY_SIZE, random);
		SecretKey key = keyGen.generateKey();
		// cfa prints key for debug
		// cfa prints key for debug
		logger.info("*** CFA debugs key in byte array: " + key.getEncoded().toString());
		String hexString1 = new BigInteger(1, key.getEncoded()).toString(16);
		logger.info("*** CFA debugs key in hexa: " + hexString1);
		// Encrypt

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		final byte[] nonce = new byte[GCM_NONCE_LENGTH];
		random.nextBytes(nonce);
		// cfa prints nonce for debug
		logger.info("*** CFA debugs nonce in byte array: " + nonce.toString());
		String hexString2 = new BigInteger(1, nonce).toString(16);
		logger.info("*** CFA debugs nonce in hexa: " + hexString2);
		GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
		// cfa prints spec for debug
		logger.info("*** CFA debugs spec (IV) in byte array: " + spec.getIV().toString());
		String hexString3 = new BigInteger(1, spec.getIV()).toString(16);
		logger.info("*** CFA debugs spec (IV) in hexa: " + hexString3);

		// Encrypt
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		byte[] aad = "SecurityAAD".getBytes();
		;
		cipher.updateAAD(aad);
		byte[] cipherText = cipher.doFinal(input);
		System.out.println("cipherText: " + cipherText.toString());
		String hexString0 = new BigInteger(1, cipherText).toString(16);
		System.out.println("*** CFA debugs cipherText in hexa: " + hexString0);
		// Decrypt; nonce is shared implicitly
		cipher.init(Cipher.DECRYPT_MODE, key, spec);

		// EXPECTED: Uncommenting this will cause an AEADBadTagException when
		// decrypting
		// because AAD value is altered
		if (testNum == 1)
			aad[1]++;

		cipher.updateAAD(aad);

		// EXPECTED: Uncommenting this will cause an AEADBadTagException when
		// decrypting
		// because the encrypted data has been altered
		if (testNum == 2)
			cipherText[10]++;

		// EXPECTED: Uncommenting this will cause an AEADBadTagException when
		// decrypting
		// because the tag has been altered
		if (testNum == 3)
			cipherText[cipherText.length - 2]++;

		try {
            
            // cfa prints full cipher text for debug
            
            byte[] plainText = cipher.doFinal(cipherText);
            if (testNum != 0) {
            	logger.info("Test Failed: expected AEADBadTagException not thrown");
            } else {
                // check if the decryption result matches
            	logger.info(String.valueOf(Arrays.equals(input, plainText)));
                if (Arrays.equals(input, plainText)) {
                    logger.info("Test Passed: match!");
                    logger.info(new String(plainText));
                } else {
                    logger.info("Test Failed: result mismatch!");
                    logger.info(new String(plainText));
                }
            }
        } catch (AEADBadTagException ex) {
			if (testNum == 0) {
				logger.info("Test Failed: unexpected ex " + ex);
				ex.printStackTrace();
			} else {
				logger.info("Test Passed: expected ex " + ex);
			}
		}
	}
}