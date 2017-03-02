package com.kevin;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Random;

/*****************************************************
 * CSS577 Project 1 created by Kevin Wu.
 * Perform HMAC on SHA256 or SHA512
   -- with 3DES, AES128, and AES256.

 *Keys generation progress:
 * password input + salt -> KDF => Kmaster
 * Kmaster -> KDF+ salted message => Khmac
 * Kmaster -> KDF+ salted message => Kenc
 *
 * The KDF that is being used in this project is PBKDF2.
 * IV is stored in hexadecimal format.
 * Output of encryption algorithms is being encoded in base64.
 * AES256 is being padded in PKCS7 while AES128 and 3DES
 *    padded in PKCS5.
 ******************************************************/
public class Main {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidCipherTextException, InvalidKeySpecException {
        Security.addProvider( new BouncyCastleProvider());

        String ID = "";
        int iteration = 100000;
        String masterSalt = "thisismymastersalt";
        String encSalt = "thisismyencsalt";
        String hmacSalt = "thisismyhmacsalt";
        String Kenc = "";
        String Khmac = "";
        byte [] IV = new byte[16];
        String encrypout = "";
        String mess = new String(Files.readAllBytes(Paths.get("message.txt")));

        //read in identifiers
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String encrypt = "";
        while(true) {
            System.out.println("Please enter Encryption algorithm(3des, aes128, aes256): ");
            String encryptoption = br.readLine();

            if ((encryptoption.compareToIgnoreCase("3des")== 0 )||
                    (encryptoption.compareToIgnoreCase("aes128")== 0) ||
                    (encryptoption.compareToIgnoreCase("aes256")== 0)){
                encrypt = encryptoption;
                break;
            }else{
                System.out.println("Please select from the options.");
            }
        }
        System.out.println("==> You have selected: " + encrypt);

        String hash = "";
        while(true) {
            System.out.println("Please enter Hash algorithm(sha256, sha512): ");
            String encryptoption = br.readLine();

            if ((encryptoption.compareToIgnoreCase("sha256")== 0 )||
                    (encryptoption.compareToIgnoreCase("sha512")== 0)){
                hash = encryptoption;
                break;
            }else{
                System.out.println("Please select from the options.");
            }
        }
        System.out.println("==> You have selected: " + hash);
        String passselection = "";
        System.out.println();

        System.out.println("Enter d"+" to set password to default, or   ");
        System.out.println("type in your password and press [Enter]:  ");
        passselection = br.readLine();


        //Select and save the password
        String pass= "";
        if(passselection.compareToIgnoreCase("d") == 0){
            pass= "password";
        }else{
            pass = passselection;
        }
        System.out.println("==> Password is set to: "+pass);
        System.out.println();

        File file = new File("password.txt");
        if(!file.exists()){
            file.createNewFile();
        }
        try (FileWriter w = new FileWriter(file.getAbsoluteFile())){
            BufferedWriter bufw = new BufferedWriter(w);
            bufw.write(pass);
            bufw.close();
        }catch(IOException e){ }

        //Generate Kmaster, Kenc, Khmac
        String pas = new String(Files.readAllBytes(Paths.get("password.txt")));

        // salt the password, generate Kenc, Khmac from PBKDF2
        ID = "0";
        KeySpec spec = new PBEKeySpec(pas.toCharArray(), masterSalt.getBytes(), iteration, (32*8));
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        if(hash.compareToIgnoreCase("sha512") == 0){
            ID = "1";
            spec = new PBEKeySpec(pas.toCharArray(), masterSalt.getBytes(), iteration, (64*8));
            f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        }
        byte[] mk = f.generateSecret(spec).getEncoded();

        //===================
        // generate Khmac
        KeySpec hmacspec = new PBEKeySpec(toHex(mk).toCharArray(), hmacSalt.getBytes(), iteration, (32*8));
        if(hash.compareToIgnoreCase("sha512") == 0) {
            hmacspec = new PBEKeySpec(toHex(mk).toCharArray(), hmacSalt.getBytes(), iteration, (64*8));
        }
        byte[] ks = f.generateSecret(hmacspec).getEncoded();
        Khmac = toHex(ks);

        //===================
        // generate Kenc
        if(encrypt.compareToIgnoreCase("aes256") == 0) {
            KeySpec encspec = new PBEKeySpec(toHex(mk).toCharArray(), encSalt.getBytes(), iteration, (32 * 8));
            ks = f.generateSecret(encspec).getEncoded();
        }else{
            KeySpec encspec = new PBEKeySpec(toHex(mk).toCharArray(), encSalt.getBytes(), iteration, (16 * 8));
            ks = f.generateSecret(encspec).getEncoded();
        }
        Kenc = toHex(ks);


        //============================================================
        //encrypt the plaintext in: 3des, aes128, or aes256
        //============================================================
        Random r = new Random();
        String s = "";
        for(int x = 0; x < IV.length; x++){
            s += (Integer.toHexString(r.nextInt(15)));
        }
        IV = s.getBytes(StandardCharsets.UTF_8);


        if(encrypt.compareToIgnoreCase("3des") == 0) {
            ID = ID + "00";
            //key size = 128bit, 32 hex, 16byte, IV = 8 byte
            IV = new byte[8];
            Random ran = new Random();
            String ivtemp = "";
            for(int x = 0; x < IV.length; x++){
                ivtemp += (Integer.toHexString(ran.nextInt(15)));
            }

            IV = ivtemp.getBytes(StandardCharsets.UTF_8);

            System.out.println("==========================================================================");
            System.out.println("original message: " + mess );

            SecretKey key = new SecretKeySpec(DatatypeConverter.parseHexBinary(Kenc), "DESede");
            IvParameterSpec iv = new IvParameterSpec(IV);
            Cipher encipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            encipher.init(Cipher.ENCRYPT_MODE, key,iv);
            byte[] plainmessage = mess.getBytes("UTF8");
            byte[] cipherT = encipher.doFinal(plainmessage);
            byte[] en = Base64.getEncoder().encode(cipherT);
            encrypout = new String(en);
            System.out.println("ciphertext: " + encrypout );


            /*
            //decrypt
            System.out.println();
            System.out.println("=============================================");
            System.out.println("Start decryption");
            System.out.println("ciphertext: " + encrypout);
            byte[] decoded = Base64.getDecoder().decode(encrypout.getBytes());
            final SecretKey keys = new SecretKeySpec(DatatypeConverter.parseHexBinary(Kenc), "DESede");
            final IvParameterSpec ivs = new IvParameterSpec(IV);
            final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, keys, ivs);
            final byte[] plain = decipher.doFinal(decoded);
            System.out.println("plaintext: " + new String(plain));
            System.out.println("=============================================");
            */



        }else if(encrypt.compareToIgnoreCase("aes128") == 0){
            ID = ID + "01";
            //key size = 128bit, 32 hex, 16byte, IV = 16 byte

            Cipher en = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            SecretKeySpec enKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(Kenc), "AES");
            AlgorithmParameterSpec IVs = new IvParameterSpec(IV);
            en.init(Cipher.ENCRYPT_MODE, enKey, IVs);
            System.out.println("==========================================================================");
            System.out.println("original message: " + mess );
            byte[] message = en.doFinal(mess.getBytes());
            //encode output in base64
            byte[] encodedcipher = Base64.getEncoder().encode(message);
            encrypout = new String(encodedcipher);
            System.out.println("ciphertext: " + encrypout );

            /*
            //decrypt
            System.out.println();
            System.out.println("=============================================" );
            System.out.println("Start decryption" );
            System.out.println("ciphertext: " + encrypout );
            byte[] decoded = Base64.getDecoder().decode(encrypout.getBytes());
            SecretKeySpec dnKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(Kenc), "AES");
            Cipher de = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            de.init(Cipher.DECRYPT_MODE, dnKey, IVs);
            byte[] plain = de.doFinal(decoded);
            System.out.println("plaintext: " + new String(plain));
            System.out.println("=============================================" );
            */


        }else if(encrypt.compareToIgnoreCase("aes256") == 0){
            ID = ID + "10";
            //key size = 256bit, 64 hex, 32byte, IV = 16 byte
            System.out.println("==========================================================================");
            System.out.println("original message: " + mess );

            byte [] data = mess.getBytes();
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(DatatypeConverter.parseHexBinary(Kenc)), IV);
            cipher.init(true, ivAndKey);
            int minSize = cipher.getOutputSize(data.length);
            byte[] outBuf = new byte[minSize];
            int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
            int length2 = cipher.doFinal(outBuf, length1);
            int actualLength = length1 + length2;
            byte[] result = new byte[actualLength];
            System.arraycopy(outBuf, 0, result, 0, actualLength);

            //encode output in base64
            byte[] en = Base64.getEncoder().encode(result);
            encrypout = new String(en);
            System.out.println("ciphertext: " + encrypout );

            /*
            //decrypt
            System.out.println();
            System.out.println("=============================================" );
            System.out.println("Start decryption" );
            System.out.println("ciphertext: " + encrypout );
            byte[] decoded = Base64.getDecoder().decode(encrypout.getBytes());
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            CipherParameters iivAndKey = new ParametersWithIV(new KeyParameter(DatatypeConverter.parseHexBinary(Kenc)), IV);
            aes.init(false, iivAndKey);
            int deminSize = aes.getOutputSize(decoded.length);
            byte[] ooutBuf = new byte[deminSize];
            int delength1 = aes.processBytes(decoded, 0, decoded.length, ooutBuf, 0);
            int delength2 = aes.doFinal(ooutBuf, delength1);
            int deactualLength = delength1 + delength2;
            byte[] plain = new byte[deactualLength];

            System.arraycopy(ooutBuf, 0, plain, 0, deactualLength);
            System.out.println("plaintext: " + new String(plain));
            System.out.println("=============================================" );
            */

        }else{
            System.out.println("Error: Encryption not supported, please try again.");
            System.exit(-1);
        }

        mess = "";
        mess += new String(IV);
        mess += encrypout;
        //Store the IV
        File newFile = new File("IV.txt");
        if(!newFile.exists()){
            newFile.createNewFile();
        }
        try (FileWriter w = new FileWriter(newFile.getAbsoluteFile())){
            BufferedWriter bufw = new BufferedWriter(w);
            bufw.write(new String(IV));
            bufw.close();
        }catch(IOException e){ }

        ID = ID+ iteration;
        ID = ID + masterSalt + hmacSalt + encSalt;

        //============================================================
        //============================================================
        //encrypt with hmac: sha256 or sha512
        String liboutput = "";


        if((hash.compareToIgnoreCase("sha256") == 0)){
            SecretKeySpec keys = new SecretKeySpec((Khmac).getBytes("UTF-8"), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keys);

            liboutput = printoutput(mac.doFinal(mess.getBytes("ASCII")));

        }else if((hash.compareToIgnoreCase("sha512") == 0)){
            SecretKeySpec keys = new SecretKeySpec((Khmac).getBytes("UTF-8"), "HmacSHA512");
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(keys);

            liboutput = printoutput(mac.doFinal(mess.getBytes("ASCII")));
        }


        ID = ID + liboutput + new String(IV) + encrypout;
        System.out.println();
        System.out.println("=================================  Output of " + hash+" "+ encrypt+ " PBKDF2 =================================");
        System.out.println(ID);


        File newhFile = new File("finaloutput.txt");
        if(!newhFile.exists()){
            newhFile.createNewFile();
        }
        try (FileWriter w = new FileWriter(newhFile.getAbsoluteFile())){
            BufferedWriter bufw = new BufferedWriter(w);
            bufw.write(ID);
            bufw.close();
        }catch(IOException e){ }


    }

    private static String printoutput(byte[] bytes){
        StringBuffer buff = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                buff.append('0');
            }
            buff.append(hex);
        }
        return buff.toString();
    }

    //function changes byte array into Hex format string
    private static String toHex(byte[] bytearray){
        BigInteger big = new BigInteger(1, bytearray);
        String hexoutput = big.toString(16);
        int paddingLength = (bytearray.length * 2) - hexoutput.length();
        if(paddingLength > 0)
            return String.format("%0" + paddingLength + "d", 0) + hexoutput;
        else
            return hexoutput;
    }
}
