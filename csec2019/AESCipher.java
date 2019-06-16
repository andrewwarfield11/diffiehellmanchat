
package csec2019;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

import csec2019.AES;
import csec2019.CSec2019Prov;


public class AESCipher extends CipherSpi {
    byte[] iv = new byte[16];
    boolean do_pad;
    boolean do_cbc;
    AES cipher;
    int bufferOffset;
    byte[] buffer = new byte[16];
    boolean ENCRYPT_MODE;

    protected void engineSetMode(String mode)
      throws NoSuchAlgorithmException {
        if (mode.equals("CBC")) {
            do_cbc = true;
        } else if (mode.equals("ECB")) {
            do_cbc = false;
        } else {
            throw new NoSuchAlgorithmException();
        }
    }
    protected void engineSetPadding(String padding)
      throws NoSuchPaddingException {
        if (padding.equals("NoPadding")) {
            do_pad = false;
        } else if (padding.equals("PKCS5Padding")) {
            do_pad = true;
        } else {
            throw new NoSuchPaddingException();
        }
    }
    protected int engineGetBlockSize() {
        return 16; // This is constant for AES. 16 bytes
    }
    protected int engineGetOutputSize(int inputLen) {
        /**
         * Returns the length in bytes that an output buffer would need to be in order to hold
          the result of the next update or doFinal operation, given the input length inputLen (in bytes).
          This call takes into account any unprocessed (buffered) data from a previous update call, padding, and AEAD tagging. 
         */
         // Should probably work
         if(!do_pad | !ENCRYPT_MODE)
         {
            return inputLen;
         }
         else
         {
            int final_block = (inputLen) % 16;
            int byteNum = inputLen + 16 - final_block;
            return byteNum;
         }         
    }
    protected byte[] engineGetIV() {
        byte[] retiv = new byte[16];
        System.arraycopy(iv, 0, retiv, 0, 16);
        return retiv;
    }
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters ap = null;
        try {
            ap = AlgorithmParameters.getInstance("AES");
            ap.init(new IvParameterSpec(engineGetIV()));
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Internal Error: " + e);
        } catch (InvalidParameterSpecException e) {
            System.err.println("Internal Error: " + e);
        }
        return ap;
    }
    protected void engineInit(int opmode, Key key, SecureRandom random)
      throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Internal Error: " + e);
        }
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException {
        try {
            engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
        } catch (InvalidParameterSpecException e) {
            System.err.println("Internal Error: " + e);
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Internal Error: " + e);
        } 
    }
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {

         // params is IV or null. If null, no iv specified (can't be null for decryption)   
         
         try {
            cipher = new AES(key.getEncoded());
         } catch(Exception e) {throw new InvalidKeyException(e);}
         
         // get IV and possibly set it
         // opmode of 0 is encrypt, anything else is decrypt
         
         // rewriting this to deal with cbc or ebc (iv or no iv)
         if(opmode == Cipher.ENCRYPT_MODE)
         {
             ENCRYPT_MODE = true;
             //System.out.println("Encryption mode");
             // Iv possibly omitted, generate randomly
            
            if(do_cbc) // CBC mode encryption
            {
               // requires IV
               if(params == null)
               { // generate Iv
                   //iv = random.nextBytes(iv);
                   random.nextBytes(iv);
               }
               else
               {
                  //get IV and put it in this.iv
                    this.iv = ((IvParameterSpec) params).getIV(); // cast params to get IV
                    if (this.iv.length != this.engineGetBlockSize()) {
                        throw new InvalidAlgorithmParameterException("IV block length is invalid.");
                    }
               }
                  
            }
            else // ECB mode encryption
            {
               // should have no paramter
               // throw bad argument exception
               if(params!=null)
               {throw new InvalidAlgorithmParameterException("Must not include IV parameter for ECB");}
            }
             
         }
         else // decryption
         {
            //System.out.println("Decryption Mode");
            
            if(do_cbc) // CBC mode decryption
            { // IV is mandatory
               if(params == null)
               {
                  throw new InvalidKeyException("Must provide IV for cbc decryption");
               }
               else if(!(params instanceof IvParameterSpec))
               {throw new InvalidAlgorithmParameterException("Parameter must be of type IvParameterSpec");}
         
               else
               {
                  //get IV and put it in this.iv
                    this.iv = ((IvParameterSpec) params).getIV();
                    if (this.iv.length != this.engineGetBlockSize()) {
                        throw new InvalidAlgorithmParameterException("IV block length is invalid.");
                    }
               }
               
            }
            else // ECB mode decryption
            {
               // ECB mode = no paramter
               // throw bad argument exception if a param is passed
               if(params!=null)
               {throw new InvalidAlgorithmParameterException("Must not include IV paramter for ECB");}
            }
             // Iv is mandatory, throw Invalid Key Exception otherwise
         }
    }
    private int allocateSize(int inputLen) {
        /**
         * Implement me.
         */
         return inputLen;
    }
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = new byte[allocateSize(inputLen)];
        int size = 0;
        try {
            size = engineUpdate(input, inputOffset, inputLen, output, 0);
        } catch (ShortBufferException e) {
            System.err.println("Internal Error: " + e);
        }
        return Arrays.copyOf(output, size);
    }
    
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
        // no need to worry about padding here (done in engineFinal)
        // all encrypt/decrypt here
        byte[] temp = new byte[16];
        byte[] prev = new byte[16];
        if(ENCRYPT_MODE) // ENCRYPTION MODE
        {
            //ystem.out.println("Encrypting in engineUpdate");
            if(this.do_cbc) // encrypt with CBC
            {
                 try
                 {
                    //System.out.println("CBC Mode");
                    // IV needs to be added to first block.
                    System.arraycopy(this.engineGetIV(),0,prev,0,16);
                    int i=0;
                    for(int j=0; j<this.engineGetBlockSize(); j++)
                    {
                       temp[j] = (byte) (prev[j] ^ input[j]); // xor input and IV  byte by byte
                    }

                    byte[] cipherText = cipher.encrypt(temp);
                    System.arraycopy(cipherText,0,prev,0,16); // copy the array into prev to use for future xor
                    System.arraycopy(cipherText,0,output,0,16); // put the encrypted ciphertext into the output array
                    //System.out.println("after encrypt first block");
                    //for (byte b : output) {
                        //System.out.print(b + " ");
                    //}
                    //System.out.println();
                    // should repeat for the remaining blocks, xoring the new plain text with the prev encrypted text
                    //System.out.print("Number of blocks to encrypt: ");
                    //System.out.println(inputLen/this.engineGetBlockSize());
                    for(int b = 1; b<inputLen/this.engineGetBlockSize();b++) // b = which block it's on
                    {
                        //System.out.println("encrypt " + (b+1) + "th block");
                       for(int j=0;j<this.engineGetBlockSize();j++) // should run for one block
   
                       {
                           temp[j] = (byte) (prev[j] ^ input[j+b*this.engineGetBlockSize()]); // xor input and IV  byte by byte
                       }
                       cipherText = cipher.encrypt(temp);
                       System.arraycopy(cipherText, 0, output, b*this.engineGetBlockSize(), 16); // copies the encrypted array into the output array at the proper place
                       System.arraycopy(cipherText,0,prev,0,16);

                    }

                  } 
                  catch(Exception e) {
                  System.err.println(e);
               }

            }
            else // encrypt without CBC (make sure block length is multiple of 16)
            {
               try
               {
                  for(int b=0; b<inputLen/this.engineGetBlockSize();b++) // j represents block number
                  {
                     /**
                     for(int i =0; i<this.engineGetBlockSize(); i++)
                     {
                        temp[i] = input[i+b*this.engineGetBlockSize()]; 
                     }
                     **/
                     System.arraycopy(input, b*this.engineGetBlockSize(), temp, 0, 16);
                     byte[] cipherText = cipher.encrypt(temp);
                     System.arraycopy(cipherText, 0, output, b*this.engineGetBlockSize(), 16);
                     /**
                     for(int i=0;i<this.engineGetBlockSize();i++) // puts the encrypted ciphertext into the output array from the temporary array "array"
                     {
                        output[i+b*this.engineGetBlockSize()] = array[i];
                     }
                     **/
                  }
               }
               catch(Exception e) {
                  System.err.println(e);
               }
           }
        }
        else // DECRYPTION MODE
        {
            //System.out.println("Decrypting . . .");
            byte[] decrypted = new byte[16];
            if(this.do_cbc) // decrypt with CBC
            {
                try {
                    
                    int i = 0; // keeps track of the location in the input
                    prev = this.engineGetIV(); // iv is prev for the first block

                    //while(i < inputLen) {
                    for(int b=0; b<inputLen/this.engineGetBlockSize();b++)
                    {
                        System.arraycopy(input, b*engineGetBlockSize(), temp, 0, 16);
                        decrypted = cipher.decrypt(temp);

                        for(int j=0; j<engineGetBlockSize(); j++)
                        {
                           byte prevByte = temp[j];
                           temp[j] = (byte) (decrypted[j]^prev[j]);
                           prev[j] = prevByte;
                        }
                        System.arraycopy(temp,0,output,i,16);
                        i+= engineGetBlockSize();
                        if(i > inputLen) {
                            throw new IllegalBlockSizeException("Input length must be a multiple of block size");
                        }
                        System.arraycopy(temp,0,output,b*engineGetBlockSize(),16);
                        //System.out.println(new String(output));
                        //i+= engineGetBlockSize();
                        
                    }
                     
                }
                catch(Exception e) {System.err.println("Not enough room in buffer: " + e);}
            }
            else // decrypt without CBC (block lenth should be multiple of 16)
            {
                try {
                    int i = 0; // keeps track of the location in the input
                    while(i < inputLen) {
                        System.arraycopy(input, i, temp, 0, this.engineGetBlockSize());
                        decrypted = cipher.decrypt(temp);
                        System.arraycopy(decrypted, 0, output, i, this.engineGetBlockSize());
                        i += this.engineGetBlockSize();
                        if (i > inputLen) {
                            throw new IllegalBlockSizeException("Input length must be a multiple of block size");
                        }
                    }
                }
                catch(Exception e) {System.err.println("Not enough room in buffer: " + e);}
            }

        }
        return inputLen;
        // return length in bytes of output data produced
    }
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
        try {
            byte[] temp = new byte[engineGetOutputSize(inputLen)];
            int len = engineDoFinal(input, inputOffset, inputLen, temp, 0);
            return Arrays.copyOf(temp, len);
        } catch (ShortBufferException e) {
            System.err.println("Internal Error: " + e);
            return null;
        }

    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
       // try
       //{
           //System.out.print("Input Length: ");
           //System.out.println(inputLen);
           int padNum=0;
           int pad_length = 0;
           if(ENCRYPT_MODE) //encrypting
           {
             //System.out.println("Encrypting message");
             // first, if padding is needed, pad the last block. input length should then be a multiple of 16
             // adds a block to the end to pad if is already multiple of 16
             if(do_pad)
             {
               padNum = 16 - (inputLen % 16);
               input = Arrays.copyOf(input, inputLen + padNum);
               for(int i=0; i<padNum;i++)
               {
                   input[i+inputLen] = (byte)padNum;
                   //System.out.print("Adding this byte to pad: ");
                   //System.out.println((int) input[i+inputLen]);
               }
               //System.out.print("Plaintext length should be multiple of 16: ");
               //System.out.println(input.length);
               
               
      
             }
             else // no padding specified
             {
                  if(inputLen % engineGetBlockSize() != 0)
                         throw new IllegalBlockSizeException("The input size is not a multiple of 16 yet no padding is specified");
             }
            engineUpdate(input, 0, inputLen+padNum, output, 0);
            }
            else // decrypting
            {
                engineUpdate(input, 0, inputLen+padNum, output, 0);
                if(do_pad) // verify padding
                {
                  //System.out.print("First thing in decrypted byte array: ");
                 // System.out.println(output[0]);
                  
                  //System.out.print("Padding number: ");
                  pad_length = (int) output[inputLen-1]; // gets the last number from the input
                  //System.out.println(pad_length);
                  for(int i=0; i<pad_length; i++)
                  {
                    if( ((int) output[inputLen - 1 - i])!=pad_length) // check for each padded bit
                    {
                        throw new BadPaddingException("The padding verification failed");
                    } // padding is wrong
                    else
                    {
                        output[inputLen -1 - i] = (byte) 0; // clear padding
                    }
                  }
                }
                else // no padding specified
                {
                    if (inputLen % engineGetBlockSize() != 0)
                        throw new IllegalBlockSizeException("The input size is not a multiple of 16 yet no padding is specified");
                }
             }
               //return Arrays.copyOf(engineUpdate(input, 0, inputLen+padNum, output, 0), inputLen); // returns only the length of the input, cuts off the padding
             //System.arraycopy(input, 0, output, 0, inputLen+ padNum);
             return inputLen + padNum - pad_length; // returns the length of the output (if padding is added and in decryption mode, will remove pad length
             
          //}
        /*catch(IllegalBlockSizeException e) // if no pdding was specified but the plaintext was not a multiple of the block size
        {
          System.err.println("Internal Error: " + e);
        }*/
        /* Was getting error that these are never thrown.
        catch(ShortBufferException e)
        {
          System.err.println("Internal Error: " + e);
        }
        */
        /*catch(BadPaddingException e) //if this cipher is in decryption mode, and (un)padding has been requested, but the decrypted data is not bounded by the appropriate padding bytes
        {
          System.err.println("Internal Error: " + e);
        }*/
        //return 0;     
    }
    // simple method to go through xor of each bit
    private byte[] xor(byte[] cipher, byte[] plain)
    {
        byte[] temp = new byte[this.engineGetBlockSize()];
        for(int j=0; j<this.engineGetBlockSize();j++)
        {
            temp[j] = (byte)(cipher[j] ^ plain[j]);
        }
        return temp;
    }
}
