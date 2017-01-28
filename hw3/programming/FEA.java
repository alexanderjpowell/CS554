import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FEA
{
	public static void main(String[] args) throws Exception
	{
		if (!((args.length == 1) || (args.length == 5)))
		{
			System.out.println("Invalid usage");
			System.exit(1);
		}
		if (args[0].equals("genkey"))
		{
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			String publicKeyFilename = "public_key";
			byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
			FileOutputStream fos = new FileOutputStream(publicKeyFilename);
			fos.write(publicKeyBytes);
			fos.close();
			String privateKeyFilename = "private_key";
			byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
			fos = new FileOutputStream(privateKeyFilename);
			fos.write(privateKeyBytes);
			fos.close();
			
		}
		else if (args[0].equals("send"))
		{
			// java FEA send [sender_private_key] [receiver_public_key] [plaintext file] [ciphertext file]
			String sender_private_key = readFile(args[1]);
			String receiver_public_key = readFile(args[2]);
			String plaintext_fileName = readFile(args[3]);
			String ciphertext_fileName = args[4];

			//System.out.println(plaintext_fileName);
			/*
			System.out.println(args[3]);
			String data = readFile(plaintext_fileName);
			System.out.println("data");
			System.out.println(data);
			*/
			//FileInputStream in = new FileInputStream(args[3]);
			FileOutputStream out = new FileOutputStream(ciphertext_fileName);
			String iv   = "8765432112345678";
			String key  = "1234567887654321";
			String data = plaintext_fileName;
			//String data = readFile(plaintext_fileName);
			byte[] enc = encrypt(key, iv, data.getBytes());
			out.write(enc);
			out.close();
		}
		else if (args[0].equals("receive"))
		{
			// java FEA receive [receiver_private_key] [sender_public_key] [ciphertext file] [plaintext file]
			String receiver_private_key = readFile(args[1]);
			String sender_public_key = readFile(args[2]);
			String ciphertext_fileName = readFile(args[3]);
			String plaintext_fileName = args[4];

			FileOutputStream out = new FileOutputStream(plaintext_fileName);
			String iv   = "8765432112345678";
			String key  = "1234567887654321";
			String data = ciphertext_fileName;
			//Path path = Paths.get(ciphertext_fileName);
			//byte[] test = Files.readAllBytes(path);
			//byte[] dec = decrypt(key, iv, data.getBytes());
			//out.write(dec);
			//out.close();
		}
		else
		{
			System.out.println("Invalid usage");
		}
	}

	public static byte[] encrypt(String skey, String iv, byte[] data)
	{
		return operate(Cipher.ENCRYPT_MODE, skey, iv, data);
	}

	public static byte[] decrypt(String skey, String iv, byte[] data)
	{
		return operate(Cipher.DECRYPT_MODE, skey, iv, data);
	}

	private static byte[] operate(int mode, String skey, String iv, byte[] data)
	{
		SecretKeySpec key = new SecretKeySpec(skey.getBytes(), "AES");
		AlgorithmParameterSpec param = new IvParameterSpec(iv.getBytes());
		try
		{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(mode, key, param);
			return cipher.doFinal(data);
		}
		catch (Exception e)
		{
			System.err.println(e.getMessage());
			throw new RuntimeException(e);
		}
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







