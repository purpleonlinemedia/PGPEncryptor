import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;

public class encryptorDecryptor
{

    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException, NoSuchProviderException
    {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        }
        return pgpSecKey.extractPrivateKey(pass, "BC");
    }

    //This function handles encryption//////////////////////////////////////////////////////////////////
    public static byte[] encrypt(byte[] clearData, PGPPublicKey encKey,String fileName,boolean withIntegrityCheck, boolean armor) throws IOException, PGPException, NoSuchProviderException
    {
        if (fileName == null) {
            fileName = PGPLiteralData.CONSOLE;
        }

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        OutputStream out = encOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut); // open it with the final
        // destination
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        // we want to generate compressed data. This might be a user option
        // later,
        // in which case we would pass in bOut.
        OutputStream pOut = lData.open(cos, // the compressed output stream
                PGPLiteralData.BINARY, fileName, // "filename" to store
                clearData.length, // length of clear data
                new Date() // current time
        );
        pOut.write(clearData);

        lData.close();
        comData.close();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(),
                "BC");

        cPk.addMethod(encKey);

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes); // obtain the actual bytes from the compressed stream

        cOut.close();

        out.close();

        return encOut.toByteArray();
    }

    //This function handles decryption//////////////////////////////////////////////////////////////////
    public static byte[] decrypt(byte[] encrypted, InputStream keyIn,char[] password) throws IOException, PGPException,NoSuchProviderException, IllegalArgumentException
    {
        Security.addProvider(new BouncyCastleProvider());
        InputStream in = new ByteArrayInputStream(encrypted);
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc = null;
        Object o = pgpF.nextObject();

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        Iterator<?> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn));

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
            Logger.getLogger("PGP").log(Level.INFO, "{0}", sKey.getKeyID());
        }

        if (sKey == null) {
            throw new IllegalArgumentException(
                    "Secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(sKey, "BC");
        PGPObjectFactory pgpFact = new PGPObjectFactory(clear);
        PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();
        pgpFact = new PGPObjectFactory(cData.getDataStream());
        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
        InputStream unc = ld.getInputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int ch;

        while ((ch = unc.read()) >= 0) {
            out.write(ch);
        }

        byte[] returnBytes = out.toByteArray();
        out.close();
        return returnBytes;
    }

    public static byte[] getBytesFromFile(File file) throws IOException
    {
        InputStream is = new FileInputStream(file);

        long length = file.length();

        if (length > Integer.MAX_VALUE) {
            // File is too large
        }

        byte[] bytes = new byte[(int) length];

        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
                && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "
                    + file.getName());
        }

        is.close();
        return bytes;
    }

    private static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException
    {
        in = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);

        //
        // we just loop through the collection till we find a key suitable for
        // encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();

            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException(
                "Can't find encryption key in key ring.");
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        try {
//            testEncrypt();
            encryptFile(args[0], args[1], args[2]);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    public static void decryptFile(String encryptedFileLocation, String privateKeyLocation,String password) throws NoSuchProviderException, IOException,PGPException
    {
        byte[] encFromFile = getBytesFromFile(new File(encryptedFileLocation));

        FileInputStream secKey = new FileInputStream(privateKeyLocation);

        byte[] decrypted = decrypt(encFromFile, secKey,
                password.toCharArray());

        System.out
                .println("\ndecrypted data = '" + new String(decrypted) + "'");
    }

    public static void encryptFile(String readFileLocation,String publicKeyLocation,String outputFile) throws NoSuchProviderException, IOException,PGPException
    {
        Path path = Paths.get(readFileLocation);
        byte[] inputFileBytes = Files.readAllBytes(path);

        FileInputStream pubKey = new FileInputStream(publicKeyLocation);
        byte[] encrypted = encrypt(inputFileBytes, readPublicKey(pubKey), null,
                true, true);

        File file = new File(outputFile);

        if (!file.exists()){
            file.createNewFile();
        }

        FileWriter fileWriter = new FileWriter(file);
        fileWriter.write(new String(encrypted));
        fileWriter.flush();
        fileWriter.close();
    }

}
