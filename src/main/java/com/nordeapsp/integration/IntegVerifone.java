package com.nordeapsp.integration;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;

import com.google.common.base.Splitter;
import com.nordeapsp.integration.listener.VerifoneServletContextListener;
import com.nordeapsp.integration.util.VerifoneUtils;
import com.nordeapsp.service.dao.OrderDAO;
import com.nordeapsp.service.model.Customer;
import com.nordeapsp.service.model.Order;

public class IntegVerifone {

	// final private String agreementCode = "demo-merchant-agreement";
	final private String agreementCode = "merchant-a-test";

	private Long requestID = 0L;
	final private String softwareName = "Nordea PSP";
	final private String softwareVersion = "1.56.1.56";
	// final private String softwareVersion = "0.0.1POC";
	final private String interfaceVersion = "5"; //

	// private static final String PAYMENT_SITE_URL =
	// "https://epayment-test.point.fi/pw/payment";
	private static final String PAYMENT_SITE_URL = "https://epayment.test.point.fi/pw/payment";
	private static final String POINT_CERTIFICATE_ALIAS = "epayment.point.fi";

	// private static final String PAYMENT_SITE_URL =
	// "http://127.0.0.1:8080/pw/payment";
	// private static final String POINT_CERTIFICATE_ALIAS =
	// "epayment.point.fi";

	// private static final String PAYMENT_SITE_URL =
	// "https://t1-dmz-peosweb-1/peos-payment-web/payment";
	// private static final String POINT_CERTIFICATE_ALIAS =
	// "peossign12350597g201105";

	private static final String SHOP_SITE_URL = "http://127.0.0.1:8081/demo-shop";
	private static final String MERCHANT_AGREEMENT_CODE = "demo-merchant-agreement";
	private static final String KEYSTORE_PASSWORD = "password";
	private static final String KEY_PASSWORD = "password";
	private static final String SHOP_CERTIFICATE_ALIAS = "demo-merchant-agreement";
	private static final String SHOP_KEYSTORE_FILE = "demo-merchant-agreement.jks";

	private final SimpleDateFormat dateFormat = new SimpleDateFormat(
			"yyyy-MM-dd HH:mm:ss");

	/*
	 * private static final String SHOP_KEYSTORE_FILE =
	 * "demo-merchant-agreement-private.pem";
	 * 
	 * private static final String KEYSTORE_PASSWORD = "password"; private
	 * static final String KEY_PASSWORD = "password"; private static final
	 * String SHOP_CERTIFICATE_ALIAS = "demo-merchant-agreement";
	 */

	@Autowired
	private OrderDAO orderDAO;

	private PrivateKey shopPrivateKey;
	private PublicKey paymentPagePublicKey;

	final private String CARD_PAYMENT_SITE_URL = "https://epayment.test.point.fi/pw/serverinterface";

	private void sign(TreeMap<String, String> parameters) {

		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyStore keyStore = loadKeyStoreFomResources(
					SHOP_KEYSTORE_FILE, "jks", KEYSTORE_PASSWORD);
			shopPrivateKey = (PrivateKey) keyStore.getKey(
					SHOP_CERTIFICATE_ALIAS, KEY_PASSWORD.toCharArray());
			paymentPagePublicKey = keyStore.getCertificate(
					SHOP_CERTIFICATE_ALIAS).getPublicKey();
			System.out.println("shopPrivateKey    :"
					+ shopPrivateKey.getAlgorithm()
					+ "shopPrivateKey.toString() " + shopPrivateKey.toString());
			System.out.println("shopPublicKey    :"
					+ paymentPagePublicKey.getAlgorithm()
					+ "paymentPagePublicKey.toString() " + paymentPagePublicKey.toString());
		} catch (Exception e) {
			throw new RuntimeException("Failed to configure environment", e);
		}

		// Remove some parameters just in case they are set.
		parameters.remove("s-t-256-256_signature-one");
		parameters.remove("s-t-256-256_signature-two");
		parameters.remove("s-t-1-40_submit");
		System.out.println("Before Card No Padding1");
		String ccNumber = parameters.get("CC Number");
		String ccempiry = parameters.get("CC expiry");
		System.out.println("Before Card No Padding2");
		parameters.remove("CC Number");
		parameters.remove("CC expiry");

		System.out.println("Before Card No Padding");
		String cardPadding = formatCard(ccNumber, ccempiry,shopPrivateKey,paymentPagePublicKey);
		// String formatCard =
		// "06E538F435D2C6B4D188942B9256AC78CABD06C2CF6931A93F81E9D110E54D1A45AEEA1829FF59044DFA4D915BD753AA63CBF7F16D5D9CE09209441D62268C048C1A8DCF544483A16EAF05B5D19FA570875C24CA373749219AED9A7D58AC7D6876D19472A5211A4EFFC4533936E7BC061C1BD54EA14857B170140A869A63C0AE";

		System.out.println("cardPadding . ......  :");

		parameters.put("s-f-256-512_encrypted-card-details", cardPadding);

		// Format the parameters to correct format
		final byte[] parameterData = VerifoneUtils
				.formatParametersForSign(parameters);

		final String signatureOne = new String(Hex.encodeHex((VerifoneUtils
				.sign(parameterData, shopPrivateKey, "RSA", "SHA-1"))))
				.toUpperCase();

		System.out.println("Verifone Signature One11 : " + signatureOne);

		try {

			final byte[] signatureDataOne = Hex.decodeHex(signatureOne
					.toCharArray());
			boolean decrypptMess = VerifoneUtils.verify(parameterData,
					signatureDataOne, paymentPagePublicKey, "RSA", "SHA-1");

			System.out.println("decrypptMess.... : " + decrypptMess);
		} catch (Exception e) {
			e.printStackTrace();
		}

		parameters.put("s-t-256-256_signature-one", signatureOne);

		System.out.println("Verifone Sign End ...");
	}

	/**
	 * Set General Parameters to access Verifone API
	 * 
	 * @param parameters
	 * @param operation
	 */
	private void setGeneralParameters(TreeMap<String, String> parameters,
			String operation) {
		parameters.put("s-f-1-30_operation", operation);
		Random rand = new Random();
		int request_id = rand.nextInt((10001 + 99999) + 1) + 100001;

		parameters.put("l-f-1-20_request-id", String.valueOf(request_id));

		// parameters.put("l-f-1-20_request-id", "1");

		parameters.put("t-f-14-19_request-timestamp", new
		SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(System.currentTimeMillis()));

		//parameters.put("t-f-14-19_request-timestamp", "2016-11-04 00:00:00");

		// parameters.put("s-f-1-36_merchant-agreement-code", agreementCode);
		// parameters.put("s-f-1-30_software", "test");
		parameters.put("s-f-1-30_software", softwareName);
		parameters.put("s-f-1-10_software-version", "1");
		parameters.put("i-f-1-11_interface-version", "5");

	}

	private TreeMap<String, String> signAndSendForCardPayment(
			TreeMap<String, String> parameters) {

		sign(parameters);
		URL HttpsURL;
		TreeMap<String, String> veriResMap = new TreeMap();

		try {
			HttpsURL = new URL(CARD_PAYMENT_SITE_URL);
			HttpsURLConnection con = (HttpsURLConnection) HttpsURL
					.openConnection();
			con.setRequestMethod("POST");
			con.setDoOutput(true);
			con.setDoInput(true);

			StringBuffer requestParams = new StringBuffer();
			Iterator<String> paramIterator = parameters.keySet().iterator();
			while (paramIterator.hasNext()) {
				String key = paramIterator.next();
				String value = parameters.get(key);

				System.out.println("key  : " + key + "   value : " + value);

				requestParams.append(URLEncoder.encode(key, "UTF-8"));
				requestParams.append("=").append(
						URLEncoder.encode(value, "UTF-8"));
				requestParams.append("&");
			}

			/*
			 * OutputStreamWriter writer = new OutputStreamWriter(
			 * con.getOutputStream()); writer.write(requestParams.toString());
			 * writer.flush();
			 */

			System.out.println("requestParams   ...." + requestParams);

			DataOutputStream output = new DataOutputStream(
					con.getOutputStream());
			System.out.println("URL Connection Created");
			// output.write(VerifoneUtils.formatParametersForPost(requestParams));
			output.writeBytes(requestParams.toString());
			System.out.println("Parameters submitted to Verifone API");
			output.close();

			DataInputStream input = new DataInputStream(con.getInputStream());

			// TODO Handle response
			StringBuffer verifoneRes = new StringBuffer();

			String tmp;
			while ((tmp = input.readLine()) != null) {
				verifoneRes.append(tmp);
			}

			System.out.println("verifoneRes.toString() "
					+ verifoneRes.toString());

			String[] verResArr = verifoneRes.toString().replaceAll("&", "=")
					.split("=");

			for (int i = 0; i < verResArr.length; i = i + 2) {

				veriResMap.put(verResArr[i], verResArr[i + 1]);

			}

			input.close();

		} catch (Exception e) {

			System.out.println("Verifone Connection  Failed  ");
			// TODO Auto-generated catch block - improve error handling
			e.printStackTrace();
		}

		// TODO Save and return response "parameters"

		return veriResMap;
	}

	private String signAndSendForOnlinePayment(
			TreeMap<String, String> parameters) {

		sign(parameters);
		URL HttpsURL;
		StringBuffer verifoneRes = new StringBuffer();

		try {
			HttpsURL = new URL(PAYMENT_SITE_URL);
			HttpsURLConnection con = (HttpsURLConnection) HttpsURL
					.openConnection();
			con.setRequestMethod("POST");
			con.setDoOutput(true);
			con.setDoInput(true);

			StringBuffer requestParams = new StringBuffer();
			Iterator<String> paramIterator = parameters.keySet().iterator();
			while (paramIterator.hasNext()) {
				String key = paramIterator.next();
				String value = parameters.get(key);

				System.out.println("key  : " + key + "   value : " + value);

				requestParams.append(URLEncoder.encode(key, "UTF-8"));
				requestParams.append("=").append(
						URLEncoder.encode(value, "UTF-8"));
				requestParams.append("&");
			}
			System.out
					.println("requestParams (signAndSendForOnlinePayment)   ...."
							+ requestParams);

			DataOutputStream output = new DataOutputStream(
					con.getOutputStream());
			System.out.println("URL Connection Created");
			// output.write(VerifoneUtils.formatParametersForPost(requestParams));
			output.writeBytes(requestParams.toString());
			System.out
					.println("signAndSendForOnlinePayment submitted to Verifone API");
			output.close();

			DataInputStream input = new DataInputStream(con.getInputStream());

			// TODO Handle response

			String tmp;
			while ((tmp = input.readLine()) != null) {
				verifoneRes.append(tmp);
			}

			System.out.println("verifoneRes.toString() "
					+ verifoneRes.toString());

			input.close();

		} catch (Exception e) {

			System.out.println("Verifone Connection  Failed  ");
			// TODO Auto-generated catch block - improve error handling
			e.printStackTrace();
		}

		// TODO Save and return response "parameters"
		String payreq = "s-t-256-256_signature-one="
				+ parameters.get("s-t-256-256_signature-one") + "&"
				+ "t-f-14-19_payment-timestamp="
				+ parameters.get("t-f-14-19_payment-timestamp")
				+ "&s-f-32-32_payment-token ="
				+ parameters.get("s-f-32-32_payment-token");

		return payreq;
	}

	public void testConnection() {
		// Forcing it to a TreeMap so it's sorted, which is required by
		// Verifone.
		TreeMap<String, String> parameters = new TreeMap<String, String>();
		setGeneralParameters(parameters, "is-available");
		signAndSendForCardPayment(parameters);
	}

	/*
	 * To verify Verifone Test environment is up and running or not
	 */
	public String isVerAPIAvail() {
		TreeMap<String, String> parameters = new TreeMap<String, String>();

		setGeneralParameters(parameters, "is-available");
		TreeMap<String, String> response = signAndSendForCardPayment(parameters);
		response.size();
		String result = response.get("i-f-1-1_availability");
		return result;

	}

	/**
	 * Save Card Details @ Verifone and get Payment Method Id to process payment
	 * for a consumer
	 * 
	 * @param order
	 * @return
	 */

	public TreeMap<String, String> saveCardPayment(Order order) {

		// Save Card Payment Method
		TreeMap<String, String> parameters = new TreeMap<String, String>();

		parameters.put("s-f-1-36_merchant-agreement-code",
				orderDAO.getAgreementCode(order.getMerchant_id()));

		parameters.put("s-f-1-30_buyer-first-name",
				order.getBilling_first_name());
		parameters
				.put("s-f-1-30_buyer-last-name", order.getBilling_last_name());
		parameters.put("s-f-1-100_buyer-email-address", order.getCust_email());
		parameters.put("s-f-1-30_payment-method-code", order.getCard_type());
		//String formatCard = "06E538F435D2C6B4D188942B9256AC78CABD06C2CF6931A93F81E9D110E54D1A45AEEA1829FF59044DFA4D915BD753AA63CBF7F16D5D9CE09209441D62268C048C1A8DCF544483A16EAF05B5D19FA570875C24CA373749219AED9A7D58AC7D6876D19472A5211A4EFFC4533936E7BC061C1BD54EA14857B170140A869A63C0AE";
		// 06E538F435D2C6B4D188942B9256AC78CABD06C2CF6931A93F81E9D110E54D1A45AEEA1829FF59044DFA4D915BD753AA63CBF7F16D5D9CE09209441D62268C048C1A8DCF544483A16EAF05B5D19FA570875C24CA373749219AED9A7D58AC7D6876D19472A5211A4EFFC4533936E7BC061C1BD54EA14857B170140A869A63C0AE
		// String formatCard =
		// "0120170C16B90FDD10485927C31D093D1C78148E79171AC13F8A33F297C37906D33A2AF773F1A4B363B31145C651C7EB53E8288AFE811245F466EB1CE05EB6F2B86799C7EFD877250EB69863CC7345A3C6CC138F3031F9E971EC8DBEB37D041FA41EA1DB47740671B76AEB45FFF25B07FB58AE838EC8FB9E4976DCA5B39873B7DA5C87";
		// String formatcard = "4485061773165186";

		parameters.put("CC Number", order.getCc_numbers());

		parameters.put("CC expiry", order.getCc_expires());

		parameters.put("s-t-1-30_buyer-phone-number",
				order.getCustPhoneNumber());
		parameters.put("s-t-1-30_buyer-phone-number", "+3581234567");
		System.out.println("Do Payment Before signAndSend ");

		setGeneralParameters(parameters, "save-card-payment-method");

		TreeMap<String, String> verSaveCardPay = signAndSendForCardPayment(parameters);
		System.out.println("Do Payment After  signAndSend ");

		// parameters.put("s-f-256-512_encrypted-card-details", formatCard);

		
		return verSaveCardPay;

	}

	public TreeMap<String, String> refundPayment(Order order) {
		TreeMap<String, String> parameters = new TreeMap<String, String>();
		System.out.println("Refund Payment Started ......");

		// Process Payment
		parameters = new TreeMap<String, String>();
		parameters.put("s-f-1-36_merchant-agreement-code",
				orderDAO.getAgreementCode(order.getMerchant_id()));

		parameters.put("s-f-1-30_payment-method-code", "visa");
		parameters.put("l-f-1-20_transaction-number",
				String.valueOf(order.getTx_no()));
		parameters.put("i-f-1-3_refund-currency-code", "978");
		parameters.put("l-f-1-20_refund-amount", String.valueOf(order.getCurrency_value().longValue()));
		setGeneralParameters(parameters, "refund-payment");
		TreeMap<String, String> verRes_proPay = signAndSendForCardPayment(parameters);
		System.out.println("Refund payment After signAndSend ");

		return verRes_proPay;
	}

	public TreeMap<String, String> cancelPayment(Order order) {
		TreeMap<String, String> parameters = new TreeMap<String, String>();
		System.out.println("Cancel Payment Started ......");

		// Process Payment
		parameters = new TreeMap<String, String>();
		parameters.put("s-f-1-36_merchant-agreement-code",
				orderDAO.getAgreementCode(order.getMerchant_id()));

		parameters.put("s-f-1-30_payment-method-code", "visa");
		parameters.put("l-f-1-20_transaction-number",
				String.valueOf(Long.valueOf(order.getTx_no())));
				
		setGeneralParameters(parameters, "cancel-payment");
		TreeMap<String, String> verRes_proPay = signAndSendForCardPayment(parameters);
		System.out.println("Cancel payment After signAndSend ");

		return verRes_proPay;
	}

	public TreeMap<String, String> processPayment(Order order) {
		TreeMap<String, String> parameters = new TreeMap<String, String>();
		System.out.println("Process Payment Started ......");

		// Process Payment
		parameters = new TreeMap<String, String>();
		parameters.put("s-f-1-36_merchant-agreement-code",
				orderDAO.getAgreementCode(order.getMerchant_id()));
		parameters.put("locale-f-2-5_payment-locale", "fi_FI");
		parameters.put("t-f-14-19_payment-timestamp", new SimpleDateFormat(
				"yyyy-MM-dd HH:mm:ss").format(System.currentTimeMillis())); // FORMAT
		// yyyy-MM-dd
		// HH:mm:ss
		//parameters.put("s-f-1-36_order-number", "NOR10001");
		parameters.put("t-f-14-19_order-timestamp", new SimpleDateFormat(
				"yyyy-MM-dd HH:mm:ss").format(System.currentTimeMillis()));
		parameters.put("i-f-1-3_order-currency-code", "978");
		parameters.put("l-f-1-20_order-gross-amount", String.valueOf(order.getCurrency_value().longValue()));

		

		if (!"".equals(order.getBilling_first_name())) {

			System.out.println("Step    0001");

			parameters.put("s-f-1-30_buyer-first-name",
					order.getBilling_first_name());
			parameters.put("s-f-1-30_buyer-last-name",
					order.getBilling_last_name());
			parameters.put("s-f-1-100_buyer-email-address",
					order.getCust_email());
			parameters.put("s-t-1-30_buyer-phone-number",
					order.getCustPhoneNumber());
			parameters.put("s-f-1-30_payment-method-code", "visa");
			parameters.put("l-t-1-20_saved-payment-method-id",
					String.valueOf(order.getPayMethodId()));
			parameters.put("s-f-1-36_order-number",
					String.valueOf(order.getOrder_id()));
		} else {

			parameters.put("s-f-1-30_buyer-first-name", "Raj");
			parameters.put("s-f-1-30_buyer-last-name", "ja");
			parameters.put("s-f-1-100_buyer-email-address", "fss");
			parameters.put("s-t-1-30_buyer-phone-number", "9962024009");
			parameters.put("s-f-1-30_payment-method-code", "visa");
			parameters.put("l-t-1-20_saved-payment-method-id", "32323");
			parameters.put("s-f-1-36_order-number",
					String.valueOf(order.getOrder_id()));
		}
		System.out.println("Do process payment Before signAndSend ");
		parameters.put("i-t-1-3_delivery-address-country-code", "356");
		setGeneralParameters(parameters, "process-payment");
		TreeMap<String, String> verRes_proPay = signAndSendForCardPayment(parameters);
		System.out.println("Do process payment After signAndSend ");

		return verRes_proPay;
	}

	/*
	 * Remove the saved card and returns: "removed" iff successfully removed
	 * Error Message otherwise
	 */
	private String removeCard(String savedPaymentID) {
		TreeMap<String, String> parameters = new TreeMap<String, String>();
		setGeneralParameters(parameters, "remove-saved-payment-method");
		parameters.put(savedPaymentID, "l-t-1-20_saved-payment-method-id");
		TreeMap<String, String> response = signAndSendForCardPayment(parameters);

		if (response.get("l-t-1-10_removed-count").equals("1")) {
			return "removed";
		}
		return response.get("s-f-1-30_error-message");
	}

	/**
	 * Formats a card according to Verifone specifications. Which is
	 * <PAN>=<MMyyyy> padded with PKCS #1 padding and RSA encrypted and
	 * converted to upper case hexadecimal string
	 * 
	 * @param cardNumber
	 *            The card number, should only contain numbers (no whitespaces).
	 * @param cardExpiry
	 *            The Date of expiry on the card, only using at Year and Month.
	 *            Maybe change the input to Calendar instead of Date.
	 * @return The encrypted card details.
	 * @throws DecoderException 
	 */
	private String formatCard(String cardNumber, String cardExpiry,
			PrivateKey shopPrivateKey,PublicKey paymentPagePublicKey)  {

		// Format the card to correct format(<PAN>=<MMyyyy>)
		Calendar c = new GregorianCalendar();
		// c.setTime(cardExpiry);
		SimpleDateFormat format = new SimpleDateFormat("MMyyyy");

		// Remove any additional spaces (just in case) and format the Date
		// according to specs
		/*
		 * String formatedCardString = (cardNumber.replace(" ", "") + "=" +
		 * (format .format(c.getTime())));
		 */
		System.out.println("cardNumber.replace cardExpiry.trim()  :"
				+ cardNumber.replace(" ", "") + "=" + cardExpiry.trim());

		String formatedCardString = (cardNumber.replace(" ", "") + "=" + cardExpiry
				.trim());
		// Convert to bytes
		byte[] formatedCardBytes = formatedCardString.getBytes();

		// Time to encrypt the card (padded with PKCS #1 padding and RSA
		// encrypted)
		// Security.addProvider(new
		// org.bouncycastle.jce.provider.BouncyCastleProvider());

		String encryptedCard = "";
		try {
			Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
			SecureRandom random = new SecureRandom();
			// KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
			// "BC");

			// generator.initialize(256, random);

			// Assuming public key has been setup!

			System.out.println("paymentPagePublicKey  : "
					+ paymentPagePublicKey.toString());

			cipher.init(Cipher.ENCRYPT_MODE, paymentPagePublicKey, random);
			byte[] cipherText = cipher.doFinal(formatedCardBytes);

			// convert to upper case hexadecimal string
			//encryptedCard =
			//DatatypeConverter.printHexBinary(cipherText).toUpperCase();
			encryptedCard = new String(Hex.encodeHex(cipherText)).toUpperCase();
			
			String decrypted = "0C16B90FDD10485927C31D093D1C78148E79171AC13F8A33F297C37906D33A2AF773F1A4B363B31145C651C7EB53E8288AFE811245F466EB1CE05EB6F2B86799C7EFD877250EB69863CC7345A3C6CC138F3031F9E971EC8DBEB37D041FA41EA1DB47740671B76AEB45FFF25B07FB58AE838EC8FB9E4976DCA5B39873B7DA5C87";
			
			
		byte[]	decryptedbyte = Hex.decodeHex(decrypted.toCharArray());
			
			System.out.println("shopPrivateKey  : "
					+ shopPrivateKey.toString());
			 cipher.init(Cipher.DECRYPT_MODE, shopPrivateKey);
			    byte[] plainText = cipher.doFinal(decryptedbyte);
			    System.out.println("plain : " + new String(plainText));
			    
			    
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException | InvalidKeyException
				| IllegalBlockSizeException | BadPaddingException | DecoderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("encryptedCard     : " + encryptedCard);

		return encryptedCard;

	}

	private KeyStore loadKeyStoreFomResources(final String filename,
			final String keyStoretype, final String keyStorePassword)
			throws IOException {

		InputStream keyStoreInputStream = null;
		try {
			System.out.println("Inside Load Key Store Form Resources ...  "
					+ filename);
			final KeyStore keyStore = KeyStore.getInstance(keyStoretype);
			keyStoreInputStream = getClass()
					.getResourceAsStream("/" + filename);
			keyStore.load(keyStoreInputStream, keyStorePassword.toCharArray());
			return keyStore;
		} catch (Exception e) {
			throw new RuntimeException("Failed to load keystore " + filename);
		} finally {
			if (keyStoreInputStream != null) {
				keyStoreInputStream.close();
			}
		}
	}

	public String onlineBankInvoice(Order order) {

		System.out.println("Do Invoice payment Before signAndSend ");
		final TreeMap<String, String> parameters = fillParemeters("http://www.norprototype.com/payment_gateway");

		String paymentHtml = signAndSendForOnlinePayment(parameters);
		System.out.println("Do process payment After signAndSend ");

		return paymentHtml;
	}

	private TreeMap<String, String> fillParemeters(final String shopSiteUrl) {

		final TreeMap<String, String> parameters = new TreeMap<String, String>();
		final Date now = new Date();

		parameters.put("locale-f-2-5_payment-locale", "en_GB");
		parameters.put("t-f-14-19_payment-timestamp", dateFormat.format(now));

		parameters.put("s-f-1-36_merchant-agreement-code", "merchant-a-test");
		parameters.put("s-f-1-36_order-number",
				Long.toString(System.currentTimeMillis()));
		parameters.put("t-f-14-19_order-timestamp", dateFormat.format(now));
		parameters.put("s-t-1-36_order-note", "x213");
		parameters.put("i-f-1-3_order-currency-code", "978");
		parameters.put("l-f-1-20_order-net-amount", "1000");
		parameters.put("l-f-1-20_order-gross-amount", "1230");
		parameters.put("l-f-1-20_order-vat-amount", "230");
		parameters.put("i-t-1-4_order-vat-percentage", "2300");
		parameters.put("s-f-1-30_buyer-first-name", "Matti");
		parameters.put("s-f-1-30_buyer-last-name", "Meikäläinen");
		parameters.put("s-t-1-30_buyer-phone-number", "+358 50 234234");
		parameters.put("s-f-1-100_buyer-email-address",
				"john.smith@example.com");
		parameters.put("s-t-1-30_delivery-address-line-one",
				"Street Address #1");
		parameters.put("s-t-1-30_delivery-address-line-two",
				"Street Address #2");
		parameters.put("s-t-1-30_delivery-address-line-three",
				"Street Address #3");
		parameters.put("s-t-1-30_delivery-address-city", "City");
		parameters.put("s-t-1-30_delivery-address-postal-code", "00234");
		parameters.put("i-t-1-3_delivery-address-country-code", "246");

		parameters.put("s-t-1-30_payment-method-code", "");
		parameters.put("l-t-1-20_saved-payment-method-id", "");
		parameters.put("s-t-1-30_style-code", "");
		parameters.put("i-t-1-1_recurring-payment", "0");
		parameters.put("i-t-1-1_deferred-payment", "0");
		parameters.put("i-t-1-1_save-payment-method", "0");
		parameters.put("i-t-1-1_skip-confirmation-page", "0");

		parameters.put("s-f-5-128_success-url", shopSiteUrl + "/receipt");
		parameters.put("s-f-5-128_rejected-url", shopSiteUrl + "/cancel");
		parameters.put("s-f-5-128_cancel-url", shopSiteUrl + "/cancel");
		parameters.put("s-f-5-128_expired-url", shopSiteUrl + "/cancel");
		parameters.put("s-f-5-128_error-url", shopSiteUrl + "/cancel");

		parameters.put("s-t-1-30_bi-name-0", "test-basket-item-0");
		parameters.put("l-t-1-20_bi-unit-cost-0", "100");
		parameters.put("i-t-1-11_bi-unit-count-0", "1");
		parameters.put("l-t-1-20_bi-net-amount-0", "100");
		parameters.put("l-t-1-20_bi-gross-amount-0", "123");
		parameters.put("i-t-1-4_bi-vat-percentage-0", "2300");
		parameters.put("i-t-1-4_bi-discount-percentage-0", "0");

		parameters.put("s-f-1-30_software", "My Web Shop");
		parameters.put("s-f-1-10_software-version", "1.0.1");
		parameters.put("i-f-1-11_interface-version", "3");
		// parameters.put("s-t-1-32_type-of-payment", "invoice-payment");
		// parameters.put("s-t-1-30_payment-method-type",
		// "HANDELSBANKEN_SE_ACCOUNT");
		// parameters.put("s-t-1-40_submit","Submit");
		parameters.put("state", "sign-and-forward");
		parameters.put("i-t-1-1_web-terminal-payment", "0");
		parameters.put("t-f-14-19_payment-timestamp",
				dateFormat.format(new Date()));
		final String paymentTokenContent = parameters
				.get("s-f-1-36_merchant-agreement-code")
				+ ";"
				+ parameters.get("s-f-1-36_order-number")
				+ ";"
				+ parameters.get("t-f-14-19_payment-timestamp");
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA-256");
			final String digestvalue = new String(Hex.encodeHex(digest
					.digest(paymentTokenContent.getBytes(Charset
							.forName("UTF8"))))).substring(0, 32);
			parameters
					.put("s-f-32-32_payment-token", digestvalue.toUpperCase());

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-256 algorithm not available.");
		}

		return parameters;
	}

}