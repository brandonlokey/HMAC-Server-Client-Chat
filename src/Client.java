import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Client {
    private Socket socket = null;
    private Scanner input = null;
    private DataOutputStream out = null;
    private DataInputStream in = null;

    public Client(String address, int port) {
        try {
            // Generate DES + HMAC keys
            KeyGenerator DESkeygenerator = KeyGenerator.getInstance("DES");
            SecretKey myDesKey = DESkeygenerator.generateKey();
            byte[] DESkey = myDesKey.getEncoded();

            KeyGenerator HMACkeygenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey myHmacKey = HMACkeygenerator.generateKey();
            byte[] hmacKey = myHmacKey.getEncoded();

            // Connect to server
            socket = new Socket(address, port);
            System.out.println("Connected to the server.");

            // Generate ciphers
            Cipher DESencipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            DESencipher.init(Cipher.ENCRYPT_MODE, myDesKey);

            Cipher DESdecipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            DESdecipher.init(Cipher.DECRYPT_MODE, myDesKey);

            // Generate HMAC instance
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(myHmacKey);

            // Write keys to file
            File DESkeyfile = new File("DESKeyFile.txt");
            OutputStream fileStream = new FileOutputStream(DESkeyfile);
            fileStream.write(DESkey);
            fileStream.close();

            File HMACkeyfile = new File("HMACKeyFile.txt");
            fileStream = new FileOutputStream(HMACkeyfile);
            fileStream.write(hmacKey);
            fileStream.close();

            // Initialize input/output streams
            input = new Scanner(System.in);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            String sentLine = "";
            String decLine = "";
            // Take messages until "Over" entered
            while(!sentLine.equals("Over") || !decLine.equals("Over")) {
                try {
                    System.out.print("\nEnter text (Type 'Over' to stop): ");

                    // Get line + HMAC + encrypted line
                    sentLine = input.nextLine();
                    byte[] hmac = mac.doFinal(sentLine.getBytes());
                    String hmacLine = sentLine + toHexString(hmac);
                    byte[] encLine = DESencipher.doFinal(hmacLine.getBytes());

                    System.out.println("********************");
                    System.out.println("Plaintext: " + sentLine);
                    System.out.println("Shared DES Key: " + toHexString(DESkey));
                    System.out.println("Shared HMAC Key: " + toHexString(hmacKey));
                    System.out.println("Sender Side HMAC: " + toHexString(hmac));
                    System.out.println("Sent Ciphertext: " + new String(encLine));
                    System.out.println("********************");

                    // Send to server
                    out.writeInt(encLine.length);
                    out.write(encLine);

                    if (sentLine.equals("Over")) {
                        System.exit(0);
                    }

                    //Get message back from server
                    int length = in.readInt();
                    if (length > 0) {
                        //Get bytes
                        System.out.println("\nServer message");
                        byte[] message = new byte[length];
                        in.readFully(message, 0, message.length);

                        // Decipher message
                        byte[] decBytes = DESdecipher.doFinal(message);
                        decLine = new String(decBytes);

                        System.out.println("********************");
                        System.out.println("Encrypted: " + new String(message));
                        System.out.println("Key: " + DESkey);
                        System.out.println("Decrypted: " + decLine);
                        System.out.println("********************");
                    }
                }
                catch(IOException i) {
                    System.out.println(i);
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
            }

            try
            {
                input.close();
                out.close();
                socket.close();
            }
            catch(IOException i)
            {
                System.out.println(i);
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public static void main(String args[])
    {
        Client client = new Client("127.0.0.1", 5000);
    }

    public static String toHexString(byte[] hash) {
        // Convert byte array into signum representation
        BigInteger number = new BigInteger(1, hash);

        // Convert message digest into hex value
        StringBuilder hexString = new StringBuilder(number.toString(16));

        // Pad with leading zeros
        while (hexString.length() < 32) {
            hexString.insert(0, '0');
        }

        return hexString.toString();
    }
}
