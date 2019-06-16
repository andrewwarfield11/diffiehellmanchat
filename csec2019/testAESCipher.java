package csec2019;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.sun.crypto.provider.DHKeyAgreement;

import csec2019.CSec2019Prov;
import java.util.Random;


public class testAESCipher {
    public static void main(String[] args) {
         System.out.println("Inserting provider");
         Security.insertProviderAt(new CSec2019Prov(), 1);
          Cipher cipher;
          Cipher cipher2;
          try{
            /**
                        KeyPairGenerator keygen;
            KeyPair key1;
            KeyPair key2;
            PublicKey pub;
            PrivateKey pri;
            KeyFactory keyFac;
            byte[] pubKey;
            // generate secret key with dhkeyagreement
            DHKeyAgreement dh = new DHKeyAgreement();

            // generate secret key and iv with dhkeyagreement
            keygen = KeyPairGenerator.getInstance("DH");
            keygen.initialize(1024);
            key1 = keygen.generateKeyPair();
            pub = key1.getPublic();
            pri = key1.getPrivate();
            System.out.println("Generating public and private keys");
            keyFac = KeyFactory.getInstance("DH");
            System.out.println("Created keyFac");
            
   

            byte[] senderPubKey = new byte[1024];
            PublicKey senderPub = keyFac.generatePublic(new X509EncodedKeySpec(senderPubKey));
            System.out.println("Getting senderPub");
            KeyAgreement agr = KeyAgreement.getInstance("DH");
            System.out.println("Created key agreement");
            agr.init(pri);
            agr.doPhase(senderPub, true);
            byte[] secretKey = agr.generateSecret();
            System.out.println("Generated secret key");
            SecretKeySpec key = new SecretKeySpec(secretKey, 0, secretKey.length, "DH");
            **/
            Random rd = new Random();
            SecureRandom rand = new SecureRandom();
            byte[] arr = new byte[16];
            byte[] enc = new byte[16];
            byte[] dec = new byte[16];
            rd.nextBytes(arr);
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] input = {'A', 'B', 'C', 'D', 'E', 'F', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S'};
            byte[] keys = {(byte)98,(byte)15, (byte)140, (byte)182, (byte)115,  (byte)56, (byte)135, (byte)230, (byte)179,  (byte)60, (byte)230,(byte)124,  (byte)21, (byte)234, (byte)177, (byte)243};
            SecretKeySpec secret = new SecretKeySpec(keys, "AES");
            // IvParameterSpec ezIV = new IvParameterSpec(arr);
            cipher.init(cipher.ENCRYPT_MODE, secret);
            System.out.println(cipher.getProvider().getName());
            //cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //cipher2.init(cipher2.DECRYPT_MODE, secret);
            enc = cipher.doFinal(input,0,16);
            //System.out.println(enc.length);
            /**
            for(byte b: enc)
            {
               System.out.println(b);
            } 
            **/
            //dec = cipher2.doFinal(enc,0,16);
            //System.out.println(new String(dec));
          }
          catch(NoSuchAlgorithmException e) {System.err.println(e);}
          catch(NoSuchPaddingException e) {System.err.println(e);}
          catch(Exception e) {System.err.println(e);}
    }
}