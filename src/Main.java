import javax.annotation.processing.Filer;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        System.out.println("Teil 1");
        Scanner scanner = new Scanner(new InputStreamReader(System.in));
        //User inputs the text to hash
        System.out.println("Enter text to hash");
        String plainText = scanner.nextLine();

        System.out.println("Plain Text: " + plainText);
        System.out.println("MD5 HASH: " + HashMd5(plainText));
        System.out.println("SHA256 HASH: " + HashSha256(plainText));
        System.out.println("SHA256 SALT HASH: " + HashSha256Salt(plainText));
        System.out.println("BCRYPT HASH: " + HashBcrypt(plainText));

        System.out.println("--------------------------------------------------");

        System.out.println("Teil 2");
        System.out.println(FindPlainText());
    }

    public static String HashMd5(String plainText) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //System.out.println("Plain Text: " + plainText);

        //Instantiate MessageDigest Class with MD5 algorithm
        MessageDigest md = MessageDigest.getInstance("MD5");

        //returns the byte array for the md5 hash value
        byte[] theMD5digest = md.digest(plainText.getBytes("UTF-8"));

        //convert byte array which contains the digested plainText
        BigInteger bigInt = new BigInteger(1,theMD5digest);

        //converting the plainText digest into the hex value
        String hashtext = bigInt.toString(16);

        //padding with tbe leading zeros
        while (hashtext.length() < 32)
        {
            hashtext = "0" + hashtext;
        }

        //System.out.println("MD5 HASH: " + hashtext);
        return hashtext;
    }

    public static String HashSha256(String plainText) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //Instantiate MessageDigest Class with SHA-256 algorithm
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        //returns the byte array for the SHA-256 hash value
        byte[] theSHA256digest = sha256.digest(plainText.getBytes("UTF-8"));

        //convert byte array which contains the digested plainText
        BigInteger bigInt = new BigInteger(1,theSHA256digest);

        //converting the plainText digest into the hex value
        String hashtext = bigInt.toString(16);

        //padding with tbe leading zeros
        while (hashtext.length() < 32)
        {
            hashtext = "0" + hashtext;
        }

        return hashtext;
    }

    public static String HashSha256Salt(String plainText) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        //Get random secure salt
        byte[] saltArr = receiveSalt();

        //Instantiate MessageDigest Class with SHA-256 algorithm
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        //add salt to algorithm
        sha256.update(saltArr);

        //returns the byte array for the SHA-256 with salt hash value
        byte[] theSHA256digest = sha256.digest(plainText.getBytes("UTF-8"));

        //convert byte array which contains the digested plainText
        BigInteger bigInt = new BigInteger(1,theSHA256digest);

        //converting the plainText digest into the hex value
        String hashtext = bigInt.toString(16);

        //padding with tbe leading zeros
        while (hashtext.length() < 32)
        {
            hashtext = "0" + hashtext;
        }

        return hashtext;
    }

    public static byte[] receiveSalt() throws NoSuchAlgorithmException
    {
        //Instantiate Secure Random class with SHA-1 Random generator to generate a secure random salt
        SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");

        // Create an array for the salt
        byte[] salt = new byte[15];

        // Get the random salt
        secRand.nextBytes(salt);

        return salt;
    }

    public static String HashBcrypt(String plainText){
        //Based on Blowfish algorithm
        //Uses SALT
        //Designed to be costly not to be efficient
        //Bcrypt uses an additional Parameter (cost factor) to define/increase the effort for the hash calculation
        //Makes Brute Force Attacks harder because of the cost factor

        //The hashed message starts with '$' and consists of ...
        //...the version number (2a),
        //...the cost factor (10),
        //...the salt (0r.TX51ZLKXChhn7dxfcou),
        //...the hash value (GnuYH8tHnoACzOjXMtKIJ/wJ1SYUJF6)
        //e.g. $2a$10$0r.TX51ZLKXChhn7dxfcouGnuYH8tHnoACzOjXMtKIJ/wJ1SYUJF6

        // Hash a password for the first time
        String hashed = org.mindrot.jbcrypt.BCrypt.hashpw(plainText, org.mindrot.jbcrypt.BCrypt.gensalt());

        return hashed;
    }

    public static String FindPlainText() throws IOException, NoSuchAlgorithmException {
        String hash = "340d600392818df2413382dc7d8325c360d83ea49a262d31760348484bbc10b5";
        String file = "src/Ressources/rainbowTable.txt";
        BufferedReader bufferedReader = new BufferedReader(new FileReader(file));

        String line;
        String result = "Hash Not Found in RainbowTable";
        while((line = bufferedReader.readLine()) != null)
        {
            if (HashMd5(line).equals(hash))
            {
                result = "Hash: " + hash + "\nPlain Text: " + line + "\nAlgorithm: MD5";
            }
            else if(HashSha256(line).equals(hash))
            {
                result = "Hash: " + hash + "\nPlain Text: " + line + "\nAlgorithm: SHA-256";
            }
        }
        return result;
    }
}