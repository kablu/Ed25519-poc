/**
 
 *
 * This file is part of Secrete.
 *
 * Secrete is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Secrete is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Secrete.  If not, see <http://www.gnu.org/licenses/>.
 */

package net.nharyes.secrete.actions;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

import net.nharyes.secrete.curve.Curve25519PublicKey;
import net.nharyes.secrete.ecies.ECIES;
import net.nharyes.secrete.ecies.ECIESException;
import net.nharyes.secrete.ecies.ECIESMessage;

import org.apache.commons.cli.CommandLine;

public class EncryptAction extends Action {

	public void execute(CommandLine line, SecureRandom random) throws ActionException {

		System.out.println("@@inside execute.EncryptAction..");
		try {

			// read data
			Object data = readData(line.getOptionValue('i'), "message");
 
			// load public key
			String keyToLoad = DEFAULT_PUBLIC_KEY;
			if (line.hasOption('k'))
				keyToLoad = line.getOptionValue('k');
			FileInputStream fin = new FileInputStream(keyToLoad);
			//Curve25519PublicKey key = Curve25519PublicKey.deserialize(fin);
			System.out.println("Public Key Read");
			Curve25519PublicKey key = readPublicKey();
			System.out.println("Public Key Read finished..");
			// encrypt message
			ECIESMessage message;
			if (line.hasOption('i'))
				message = ECIES.encryptData(key, (byte[]) data, random);
			else
				message = ECIES.encryptData(key, (String) data, random);

			// write message
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			message.serialize(bout);
			writeData(bout.toByteArray(), line.getOptionValue('o'), true);

		} catch (IOException | ECIESException ex) {

			// re-throw exception
			throw new ActionException(ex.getMessage(), ex);
		}
	}
	
	public String executeEncrypt(SecureRandom random, String publicKey, String data) throws ActionException {

		System.out.println("@@inside execute.EncryptAction..");

		String encryptdData = null;
		try {

			// Curve25519PublicKey key = Curve25519PublicKey.deserialize(fin);
			System.out.println("Public Key Read");
			
			Curve25519PublicKey key = readPublicKey(publicKey);
			
			System.out.println("Public Key Read finished..");
			// encrypt message
			ECIESMessage message;
			message = ECIES.encryptData(key, (String) data, random);

			// write message
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			message.serialize(bout);
			encryptdData = writePublicKeyData(bout.toByteArray(), null, true);

		} catch (IOException | ECIESException ex) {
			ex.printStackTrace();
			throw new ActionException(ex.getMessage(), ex);
		}

		return encryptdData;
	}
	
	public static Curve25519PublicKey readPublicKey() throws IOException {

		System.out.println("@@inside readPublicKey..");
		byte[] pubKey = Base64.getDecoder().decode("lCI84I0Q0U0wQ/T+cxP25+a+9sK8sstBpulLa+4iqEY=".getBytes());
		
		return new Curve25519PublicKey(pubKey);
	}
	
	public static Curve25519PublicKey readPublicKey(String publicKey) throws IOException {

		System.out.println("@@inside readPublicKey..");
		byte[] pubKey = Base64.getDecoder().decode(publicKey.getBytes());
		
		return new Curve25519PublicKey(pubKey);
	}
}
