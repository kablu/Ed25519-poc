package net.nharyes.secrete;

import java.security.SecureRandom;

import net.nharyes.secrete.actions.ActionException;
import net.nharyes.secrete.actions.DecryptAction;
import net.nharyes.secrete.actions.EncryptAction;

public class Ed25519Main {

	public static void main(String[] args) {
		// Encryption
		String encdata = new Ed25519Main().encryptUsingPubKey("lCI84I0Q0U0wQ/T+cxP25+a+9sK8sstBpulLa+4iqEY=", "Mandal");

		// Decryption
		try {
			new Ed25519Main().decryptUsingPrivateKey(encdata, "IJa1FU+BZUub3QvMtjbaZOY40abKq69iuFaApQk4MWw=");
		} catch (ActionException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * @param pubKey
	 * @param data
	 * @return
	 */
	public String encryptUsingPubKey(String pubKey, String data) {
		System.out.println("@@inside encryptUsingPubKey..");
		EncryptAction encryptAction = null;
		String encryptedData = null;
		try {
			encryptAction = new EncryptAction();
			encryptedData = encryptAction.executeEncrypt(new SecureRandom(), pubKey, data);
			System.out.println("Encrypted Data:" + encryptedData);
		} catch (ActionException e) {
			e.printStackTrace();
		}

		return encryptedData;
	}

	/**
	 * 
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws ActionException
	 */
	public String decryptUsingPrivateKey(String data, String privateKey) throws ActionException {
		System.out.println("@@inside encryptUsingPubKey..");
		DecryptAction decryptAction = null;
		String decryptedData = null;
		try {
			decryptAction = new DecryptAction();
			decryptedData = decryptAction.executeDecrypt(new SecureRandom(), data, privateKey);
			
			System.out.println("decryptedData:" + decryptedData);
		} catch (ActionException e) {
			e.printStackTrace();
			throw new ActionException("Private Key Is Not Proper");
		}

		return decryptedData;
	}
}
