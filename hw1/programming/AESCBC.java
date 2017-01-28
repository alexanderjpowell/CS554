import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

class AESCBC
{
	public static void main(String[] args)
	{
		if (args[0].equals("enc"))
		{
			try
			{
				FileInputStream in = new FileInputStream("plain-in.txt");
				FileOutputStream out = new FileOutputStream("cipher-out");
				String iv   = args[1];
				String key  = args[2];
				String data = readFile("plain-in.txt");
				byte[] enc = encrypt(key, iv, data.getBytes());
				out.write(enc);
				out.close();
			}
			catch (Exception ex)
			{
				System.out.println(ex.getMessage());
			}
		}
		else if (args[0].equals("dec"))
		{
			try
			{
				FileInputStream in = new FileInputStream("cipher-in");
				FileOutputStream out = new FileOutputStream("plain-out.txt");
				String iv   = args[1];
				String key  = args[2];
				Path path = Paths.get("cipher-in");
				byte[] test = Files.readAllBytes(path);
				byte[] dec = decrypt(key, iv, test);
				out.write(dec);
				out.close();
			}
			catch (Exception ex)
			{
				System.out.println(ex.getMessage());
			}
		}
		else
		{
			System.out.println("The first argument must be either enc or dec. ");
			System.exit(-1);
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














