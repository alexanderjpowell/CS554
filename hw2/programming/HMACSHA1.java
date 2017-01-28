
// Alexander Powell
// CSCI 554 - Computer and Network Security
// Homework #2, Problem #8
// Due: March 3, 2016

import java.io.*;
import java.util.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;

public class HMACSHA1
{
	private static String convertToString(byte[] bytes)
	{
		Formatter formatter = new Formatter();
		for (byte b : bytes)
		{
			formatter.format("%02x", b);
		}
		String output = formatter.toString();
		return output.toUpperCase();
	}

	public static String HMAC(String data, String key) throws Exception
	{
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signingKey);
		return convertToString(mac.doFinal(data.getBytes("UTF-8")));
	}

	public static void main(String[] args) throws Exception
	{
		try
		{
			String key = args[0];
			String data = readFile(args[1]);
			String hmac = HMAC(data, key);
			System.out.println(hmac);
		}
		catch (Exception ex)
		{
			System.out.println(ex.getMessage());
		}
		//String hmac = calculateRHMAC("The quick brown fox jumps over the lazy dog", "key");
		//String hmac = calculateRHMAC("wqoeiepofkds;lvkporjgpodjpowjdpowjsckvrjgport495930940534ogdpoj938uridjoasdjwoaiu3qdadcvnlkfoiwkgknju97prmnmjdigcjdugidigih96k4mfobojkgkcmskqolamxmbhlhleou0toep[lkvdfkvjsdwapfoksa;lkas;d.d.d..l", "hmac123456");
	}

		// taken from http://stackoverflow.com/questions/2885173/how-to-create-a-file-and-write-to-a-file-in-java
	private static String readFile(String fileName) throws IOException
	{
		BufferedReader br = new BufferedReader(new FileReader(fileName));
		try
		{
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();
			while (line != null)
			{
				sb.append(line);
				sb.append("\n");
				line = br.readLine();
			}
			return sb.toString();
		}
		finally
		{
			br.close();
		}
	}
}





