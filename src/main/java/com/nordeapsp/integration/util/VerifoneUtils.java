package com.nordeapsp.integration.util;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Class for utility functions.
 * 
 * @author Janis Stasans
 */
public final class VerifoneUtils {

	/**
	 * Private constructor to prevent constructing of this class.
	 */
	private VerifoneUtils() {

	}

	/**
	 * Formats map of parameters to byte array for signing.
	 * 
	 * @param parameters
	 *            the parameters to be signed.
	 * @return signature.
	 */
	public static byte[] formatParametersForPost(
			final TreeMap<String, String> parameters) {

		final StringBuilder builderForPost = new StringBuilder();

		for (final Map.Entry<String, String> entry : parameters.entrySet()) {
			builderForPost.append(entry.getKey());
			builderForPost.append('=');
			builderForPost.append(entry.getValue());
			builderForPost.append('&');
		}
		String formatParametersForPost = builderForPost.substring(0,
				(builderForPost.length() - 1));
		System.out.println("formatParametersForPost : "
				+ formatParametersForPost.toString());
		return formatParametersForPost.toString().getBytes(
				Charset.forName("UTF-8"));
	}

	public static byte[] formatParametersForSign(
			final TreeMap<String, String> parameters) {

		final StringBuilder builderForsign = new StringBuilder();

		for (final Map.Entry<String, String> entry : parameters.entrySet()) {
			builderForsign.append(entry.getKey());
			builderForsign.append('=');
			builderForsign.append(entry.getValue());
			builderForsign.append(';');
		}

		System.out.println("formatParametersForSign : "
				+ builderForsign.toString());
		
		return builderForsign.toString().getBytes(Charset.forName("UTF-8"));
	}

	/**
	 * Verifies digital signature of specified data.
	 * 
	 * @param data
	 *            Signed data.
	 * @param signature
	 *            Signature.
	 * @param publicKey
	 *            Public key.
	 * @param encryptionAlgorithm
	 *            Signature algorithm.
	 * @param hashAlgorithm
	 *            Hash algorithm.
	 * @return true if signature is valid.
	 */
	public static boolean verify(final byte[] data, final byte[] signature,
			final PublicKey publicKey, final String encryptionAlgorithm,
			final String hashAlgorithm) {
		try {

			String algorithm = null;
			if (encryptionAlgorithm.equals("RSA")
					&& hashAlgorithm.equals("SHA-1")) {
				algorithm = "SHA1withRSA";
			}
			if (encryptionAlgorithm.equals("RSA")
					&& hashAlgorithm.equals("SHA-512")) {
				algorithm = "SHA512withRSA";
			}
			if (algorithm == null) {
				throw new RuntimeException("Unsupported signature algorith: "
						+ hashAlgorithm + " with " + encryptionAlgorithm);
			}

			Signature sign = Signature.getInstance(algorithm, "BC");
			sign.initVerify(publicKey);
			sign.update(data);
			return sign.verify(signature);

		} catch (final Exception e) {
			throw new RuntimeException("Error signing data.", e);
		}
	}

	/**
	 * Signs the data .
	 * 
	 * @param data
	 *            Data to sign.
	 * @param privateKey
	 *            Private key.
	 * @param encryptionAlgorithm
	 *            Signature algorithm.
	 * @param hashAlgorithm
	 *            Hash algorithm.
	 * @return Signature bytes.
	 */
	public static byte[] sign(final byte[] data, final PrivateKey privateKey,
			final String encryptionAlgorithm, final String hashAlgorithm) {

		Security.addProvider(new BouncyCastleProvider());

		try {
			String algorithm = null;
			if (encryptionAlgorithm.equals("RSA")
					&& hashAlgorithm.equals("SHA-1")) {
				algorithm = "SHA1withRSA";
			}
			if (encryptionAlgorithm.equals("RSA")
					&& hashAlgorithm.equals("SHA-512")) {
				algorithm = "SHA512withRSA";
			}
			if (algorithm == null) {
				throw new RuntimeException("Unsupported signature algorith: "
						+ hashAlgorithm + " with " + encryptionAlgorithm);
			}

			Signature sign = Signature.getInstance(algorithm, "BC");

			sign.initSign(privateKey);
			sign.update(data);
			return sign.sign();
		} catch (final Exception e) {
			throw new RuntimeException("Error signing data.", e);
		}
	}

}
