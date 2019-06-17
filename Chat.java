
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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import com.sun.crypto.provider.SunJCE;

import com.sun.crypto.provider.DHKeyAgreement;

import csec2019.*;

public class Chat {
    public static void main(String[] args) {
        Security.insertProviderAt(new CSec2019Prov(), 1);
        SecureRandom rand;
        byte[] iv = new byte[16];
        Cipher cip = null;
        Cipher sunCipher = null;
        IvParameterSpec ivparam = null;
        try{
            cip = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //System.out.println(cip.getAlgorithm());

            // System.out.println(cip.getProvider().toString());

        } catch(Exception e) {System.err.println(e);}
        //SecretKey key = new SecretKeySpec(null, "DH");
        byte[] testKey = {(byte)0, (byte)1, (byte)0, (byte)4, (byte)8, (byte) 5, (byte) 9, (byte)3, (byte)7, (byte)6, (byte)8, (byte)1, (byte)6, (byte)1, (byte)6, (byte)5};
        SecretKey key = new SecretKeySpec(testKey, "DH");
        
        //System.out.println("Args: " + args) ;
        parseArgs(new ArrayDeque<String>(Arrays.asList(args)));
        Socket c = null;
        InputStream in = null;
        OutputStream out = null;
        if (mode == SERVER) {
            try {
                ServerSocket s = new ServerSocket(port);
                c = s.accept();
                in = c.getInputStream();
                out = c.getOutputStream();
            } catch (IOException e) {
                System.err.println("There was an error opening the server:");
                System.err.println(e);
                System.exit(-3);
            } catch (SecurityException e) {
                System.err.println("You are not allowed to open the server:");
                System.err.println(e);
                System.exit(-2);
            }

            try {
                //server has to generate DH parameters and send to client
                System.out.println("Sending DH parameters to client");
                //generate algorithm parameter generator in server
                AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
                paramGen.init(1024); // key length is 1024 bits/128 bytes
                AlgorithmParameters params = paramGen.generateParameters();
                // send DH parameters to client
                out.write(params.getEncoded());

                // perform key exchange
                key = keyExchangeServer(in,out);

                // generate iv and send to client
                if(cip.getAlgorithm().toString().contains("CBC")) {
                    rand = new SecureRandom();
                    rand.nextBytes(iv);
                    ivparam= new IvParameterSpec(iv);
                    System.out.println("Generating and sending iv");
                    out.write(iv);
                }


            } catch(IOException e) {
                System.err.println(e);
                System.exit(-4);
            } catch(NoSuchAlgorithmException e) {
                System.err.println(e);
                System.exit(-4);
            }
        } else if (mode == CLIENT) {
            try {
                c = new Socket(addr, port);
                in = c.getInputStream();
                out = c.getOutputStream();
            } catch (IOException e) {
                System.err.println("There was an error connecting:");
                System.err.println(e);
                System.exit(-3);
            } catch (SecurityException e) {
                System.err.println("You are not allowed to connect:");
                System.err.println(e);
                System.exit(-2);
            }

            try {
                byte[] modeB = new byte[1024];
                int len = in.read(modeB);
                byte[] par = new byte[len];
                System.arraycopy(modeB,0,par,0,len);
                AlgorithmParameters params= AlgorithmParameters.getInstance("DH");
                params.init(par);
                System.out.println("Received DH parameters.");

                key = keyExchangeClient(in,out);

                if(cip.getAlgorithm().toString().contains("CBC")) {
                    // receive iv
                    while(true) {
                        len = in.read(iv);
                        if (len != -1)
                            break;
                    }
                    System.out.println("Received iv");
                    ivparam = new IvParameterSpec(iv);
                }

            } catch(IOException e) {
                System.err.println(e);
                System.exit(-4);
            } catch(NoSuchAlgorithmException e) {
                System.err.println(e);
                System.exit(-4);
            }
        } else {
            System.err.println("Please specify the mode.");
            printUsage();
            System.exit(-1);
        }
        try {
            System.out.println("Initializaton done. You can begin chatting.");
            System.out.println("-----------------------------------------");
            new Thread(new ChatSender(System.in, c.getOutputStream(),key, ivparam)).start();
            new Thread(new ChatReceiver(c.getInputStream(), System.out,key, ivparam, mode)).start();
        } catch (IOException e) {
            System.err.println("There was an error setting up data transfer:");
            System.err.println(e);
            System.exit(-3);
        }
    }
    private static SecretKey keyExchangeServer(InputStream in, OutputStream out) {
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("DH");
            keygen.initialize(1024); // key size is 1024 bits/128 bytes
            // use the KeyPairGenerator to generate own public and private keys
            System.out.println("Generating public and private keys");
            KeyPair key1 = keygen.generateKeyPair();
            PublicKey pub = key1.getPublic();
            PrivateKey pri = key1.getPrivate();

            // send public key
            out.write(pub.getEncoded());
            System.out.println("Sending public key");

            // recieve sneder's public key as byte array
            System.out.println("Attempting to receive key");
            boolean keyRecieved = false;
            byte[] senderPubKey = new byte[1024];
            while (!keyRecieved) {
                int keylen = in.read(senderPubKey);
                System.out.println("Reading key....");

                if (keylen > 0) {
                    keyRecieved = true;
                    System.out.println("Key is read");
                }
            }
            System.out.println("Received public key: ");

            // convert sender's byte array public key to a PublicKey
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            KeyFactory keyFac = KeyFactory.getInstance("DH");
            PublicKey senderPub = keyFac.generatePublic(new X509EncodedKeySpec(senderPubKey));

            // use KeyAgreement, own private key, and received public key to generate secret key
            KeyAgreement agr = KeyAgreement.getInstance("DH");
            agr.init(pri);
            agr.doPhase(senderPub, true);
            byte[] secretKey = agr.generateSecret();
            byte[] secretKey16 = new byte[16];
            System.arraycopy(secretKey,0,secretKey16,0,16);
            System.out.println("Generated secret key");
            return new SecretKeySpec(secretKey16, "DH");
        } catch(IOException e) {
            System.err.println("There was an error sending or receiving data: " + e);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("No such Algorithm: " + e);
        } catch (InvalidKeyException e) {
            System.err.println(e);
        } catch (InvalidKeySpecException e) {
            System.err.println(e);
        } catch(NoSuchPaddingException e) {
            System.err.println(e);
        } catch(Exception e) {
            System.err.println(e);
        }
        // if an error was found
        return null;
    }
    private static SecretKey keyExchangeClient(InputStream in, OutputStream out) {
        try {

            KeyPairGenerator keygen = KeyPairGenerator.getInstance("DH");
            keygen.initialize(1024); // key size is 1024 bits/128 bytes
            // use the KeyPairGenerator to generate own public and private keys

            System.out.println("Generating public and private keys");
            KeyPair key1 = keygen.generateKeyPair();
            PublicKey pub = key1.getPublic();
            PrivateKey pri = key1.getPrivate();

            // send public key
            out.write(pub.getEncoded());
            System.out.println("Sending public key");
            // recieve sneder's public key as byte array
            System.out.println("Attempting to receive key");
            boolean keyRecieved = false;
            byte[] senderPubKey = new byte[1024];
            while (!keyRecieved) {
                int keylen = in.read(senderPubKey);
                System.out.println("Reading key....");

                if (keylen > 0) {
                    keyRecieved = true;
                    System.out.println("Key is read");
                }
            }
            System.out.println("Received public key: ");

            // convert sender's byte array public key to a PublicKey
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            KeyFactory keyFac = KeyFactory.getInstance("DH");
            PublicKey senderPub = keyFac.generatePublic(new X509EncodedKeySpec(senderPubKey));

            // use KeyAgreement, own private key, and received public key to generate secret key
            KeyAgreement agr = KeyAgreement.getInstance("DH");
            agr.init(pri);
            agr.doPhase(senderPub, true);
            byte[] secretKey = agr.generateSecret();
            byte[] secretKey16 = new byte[16];
            System.arraycopy(secretKey,0,secretKey16,0,16);
            System.out.println("Generated secret key");
            return new SecretKeySpec(secretKey16, "DH ") ;
        } catch(IOException e) {
            System.err.println("There was an error sending or receiving data: " + e);
        } catch  (NoSuchAlgorithmException e) {
            System.err.println("No such Algorithm: " + e);
        } catch (InvalidKeyException e) {
            System.err.println(e);
        } catch (InvalidKeySpecException e) {
            System.err.println(e);
        } catch(NoSuchPaddingException e) {
            System.err.println(e);
        } catch (Exception e) {
            System.err.println(e);
        } 
        // if an error was found
        return null;
    }
    private static void parseArgs(Queue<String> args) {
        
        System.out.println("Parsing arguments...");
        // This method is getting called correctly
        System.out.println(args);
        
        while (args.peek() != null) {
            String opt = args.poll();
            
            if (opt.equals("-s")) {
                if (mode != UNSPECIFIED) {
                    printUsage();
                    System.exit(-1);
                }
                mode = SERVER;
                parsePort(args);
            } else if (opt.equals("-c")) {
                if (mode != UNSPECIFIED) {
                    printUsage();
                    System.exit(-1);
                }
                mode = CLIENT;
                parseAddr(args);
                parsePort(args);
            }
        }
    }
    private static void badPort() {
        System.err.println("Please specify a port between 1 and 65535.");
        printUsage();
        System.exit(-1);
    }
    private static void parsePort(Queue<String> args) {
        String strPort = args.poll();
        if (strPort == null) {
            badPort();
        }
        try {
            port = Integer.parseInt(strPort);
        } catch (NumberFormatException e) {
            badPort();
        }
        if (!(1 <= port && port <= 65535)) {
            badPort();
        }
    }
    private static void badAddr() {
        System.err.println("Please specify an IP address or host name.");
        printUsage();
        System.exit(-1);
    }
    private static void parseAddr(Queue<String> args) {
        String hostname = args.poll();
        if (hostname == null) {
            badAddr();
        }
        try {
            addr = InetAddress.getByName(hostname);
        } catch (UnknownHostException e) {
            System.err.println("The address '" + hostname + "' is unrecognized or could not be resolved.");
            badAddr();
        } catch (SecurityException e) {
            System.err.println("You are not allowed to resolve '" + hostname + "'.");
            System.exit(-2);
        }
    }
    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("    java Chat -s PORT");
        System.err.println("    invokes Chat in server mode attempting to listen on PORT.");
        System.err.println("");
        System.err.println("    java Chat -c ADDRESS PORT");
        System.err.println("    invokes Chat in client mode attempting to connect to ADDRESS on PORT.");
    }

    private static final byte UNSPECIFIED = 0;
    private static final byte SERVER = 1;
    private static final byte CLIENT = 2;

    private static byte mode = UNSPECIFIED;
    private static InetAddress addr = null;
    private static int port = 0;
}

class ChatSender implements Runnable {
    public ChatSender(InputStream screen, OutputStream conn, SecretKey sKey, IvParameterSpec param) {
        this.screen = new Scanner(screen);
        this.conn = new PrintStream(conn);
        SecureRandom rand = new SecureRandom();
        rand.setSeed(rand.generateSeed(10));
        try {
            cipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //System.out.println(cipherEncrypt.getProvider().toString());
            //Security.removeProvider("CSec2019");
            //sunCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // for testing
            //System.out.println(sunCipher.getProvider().toString());
            // System.out.println(sunCipher.getProvider().toString());
            //cipherEncrypt.init(Cipher.ENCRYPT_MODE, sKey, param, rand);
            cipherEncrypt.init(Cipher.ENCRYPT_MODE, sKey, param);
            //sunCipher.init(Cipher.ENCRYPT_MODE, sKey, param);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("There was an error initializing the cipher: " + e);
            System.exit(-4);
        } catch (NoSuchPaddingException e) {
            System.err.println("There was an error initializing the cipher: " + e);
            System.exit(-4);
        } catch (InvalidKeyException e) {
            System.err.println("Invalid secret key: " + e);
        } catch(InvalidAlgorithmParameterException e) {
            System.err.println("Invalid Algorithm Parameter: " + e);
        }
        //System.out.println("Initialized ciphers. You can start chatting.");
        //System.out.println("-------------------------------------");
    }
    public void run() {
        while (true) {
            String line = screen.nextLine();
            byte[] encrypted = null;
            byte[] sunEncrypted =null;
            try {
               encrypted = cipherEncrypt.doFinal(line.getBytes(), 0, line.getBytes().length);
               //sunEncrypted = sunCipher.doFinal(line.getBytes(), 0, line.getBytes().length);
               //System.out.println(new String(encrypted));
               //System.out.println(new String(sunEncrypted));
            } catch(IllegalBlockSizeException e) {
                System.err.println(e);
            } catch(BadPaddingException e) {
                System.err.println(e);
            }
            try{
            conn.write(encrypted);
            }
            catch(Exception e){System.err.println(e);}
        }
    }

    private Scanner screen;
    private PrintStream conn;
    private Cipher cipherEncrypt;
    private Cipher sunCipher;
}

class ChatReceiver implements Runnable {
    public ChatReceiver(InputStream conn, OutputStream screen, SecretKey sKey, IvParameterSpec param, byte mode) {
        this.conn = conn;
        this.screen = screen;
        this.mode = mode;
        SecureRandom rand = new SecureRandom();
        rand.setSeed(rand.generateSeed(10));
        try {
            cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //cipherDecrypt.init(Cipher.DECRYPT_MODE,sKey, param, rand);
            cipherDecrypt.init(Cipher.DECRYPT_MODE,sKey, param);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("There was an error initializing the cipher: " + e);
            System.exit(-4);
        } catch (NoSuchPaddingException e) {
            System.err.println("There was an error initializing the cipher: " + e);
            System.exit(-4);
        } catch (InvalidKeyException e) {
            System.err.println("Invalid secret key: " + e);
        } catch(InvalidAlgorithmParameterException e) {
            System.err.println("Invalid Algorithm Parameter: " + e);
        }
        //System.out.println("Initialized ciphers. You can start chatting.");
        //System.out.println("-------------------------------------");
    }
    public void run() {
        byte[] b = new byte[1024];
        byte[] decrypted = new byte[1024];
        while (true) {
            String text;
            if(mode == SERVER)
                text = "[client] ";
            else
                text = "[server] ";
            try {
                int len = conn.read(b);
                if (len == -1) break;
                try {
                    //System.out.print("Decrypting this message");
                    //System.out.println(new String(b));
                    decrypted = cipherDecrypt.doFinal(b, 0, len);
                    text += new String(decrypted);
                } catch (IllegalBlockSizeException e) {
                    System.err.println(e);
                } catch (BadPaddingException e) {
                    System.err.println(e);
                }
                screen.write(text.getBytes(), 0, text.getBytes().length);
                screen.write(10);
                //System.out.println(new String(decrypted));
                //screen.write(decrypted, 0, len);
            } catch (IOException e) {
                System.err.println("There was an error receiving data:");
                System.err.println(e);
            }
        }
    }

    private InputStream conn;
    private OutputStream screen;
    private Cipher cipherDecrypt;
    private static final byte SERVER = 1;
    private static final byte CLIENT = 2;
    private byte mode;
}
