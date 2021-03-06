/**
 * Copyright (C) 2015  Luca Zanconato (<luca.zanconato@nharyes.net>)
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

import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;

import net.nharyes.secrete.curve.Curve25519PrivateKey;
import net.nharyes.secrete.curve.Curve25519PublicKey;
import net.nharyes.secrete.ecies.ECIES;
import net.nharyes.secrete.ecies.ECIESException;
import net.nharyes.secrete.ecies.ECIESMessage;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Base64;

public class DecryptAction extends Action {

	public void execute(CommandLine line, SecureRandom random) throws ActionException {

		System.out.println("@@inside execute..DecryptAction");
		try { 

			// read data
			Object data = readData(line.getOptionValue('i'), "encrypted message");

			// get message
			ByteArrayInputStream in;
			if (!line.hasOption('i'))
				in = new ByteArrayInputStream(Base64.decodeBase64((String) data));
			else
				in = new ByteArrayInputStream((byte[]) data);
			ECIESMessage message = ECIESMessage.deserialize(in);

			// ask password
			//Console c = System.console();
			//char[] password = c.readPassword("Enter password: ");

			// load private key
			FileInputStream fin = new FileInputStream(DEFAULT_PRIVATE_KEY);
			
			//Curve25519PrivateKey key = Curve25519PrivateKey.deserialize(fin, password);
			
			System.out.println("@@inside read Curve25519PrivateKey");
			
			Curve25519PrivateKey key  = readPrivateKey();
			
			System.out.println("@@inside finished Curve25519PrivateKey");
			
			fin.close(); 

			// decrypt message
			byte[] plaintext = ECIES.decryptMessage(key, message);

			// write message
			writeData(plaintext, line.getOptionValue('o'), message.isBinary());

		} catch (IOException | ECIESException ex) {

			// re-throw exception
			throw new ActionException(ex.getMessage(), ex);
		}
	}
	
	public String executeDecrypt(SecureRandom random, String data, String privateKey) throws ActionException {

		System.out.println("@@inside execute..DecryptAction");
		
		String decryptData = null; 
				
		try { 
			ByteArrayInputStream in;
			//in = new ByteArrayInputStream((byte[]) data.getBytes());
			in = new ByteArrayInputStream(Base64.decodeBase64((String) data));
			
			ECIESMessage message = ECIESMessage.deserialize(in);

			// load private key
			//FileInputStream fin = new FileInputStream(DEFAULT_PRIVATE_KEY);
			
			//Curve25519PrivateKey key = Curve25519PrivateKey.deserialize(fin, password);
			
			System.out.println("@@inside read Curve25519PrivateKey");
			
			Curve25519PrivateKey key  = readPrivateKey(privateKey);
			
			System.out.println("@@inside finished Curve25519PrivateKey");
			
			//fin.close(); 

			// decrypt message
			byte[] plaintext = ECIES.decryptMessage(key, message);

			// write message
			decryptData = writeDecryptData(plaintext, null, message.isBinary());

		} catch (IOException | ECIESException ex) {

			// re-throw exception
			throw new ActionException(ex.getMessage(), ex);
		}
		return decryptData;
	}
	
	public static Curve25519PrivateKey readPrivateKey() throws IOException {

		System.out.println("@@inside readPrivateKey..");
		byte[] pk = java.util.Base64.getDecoder().decode("IJa1FU+BZUub3QvMtjbaZOY40abKq69iuFaApQk4MWw=".getBytes());
		
		return new Curve25519PrivateKey(pk);
	}
	
	public static Curve25519PrivateKey readPrivateKey(String privateKey) throws IOException, ActionException {

		System.out.println("@@inside readPrivateKey..");
		byte[] pk = null;
		try {
			pk = java.util.Base64.getDecoder().decode(privateKey.getBytes());
		} catch (Exception e) {
			throw new ActionException(e.getMessage());
		}
		
		
		return new Curve25519PrivateKey(pk);
	}
}
