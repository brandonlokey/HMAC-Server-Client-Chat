import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Server {
    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public Server(int port) {
        try {
            // Initialize server
            server = new ServerSocket(port);
            System.out.println("Server started.");

            System.out.println("Waiting for client");

            // Client connected
            socket = server.accept();
            System.out.println("Client accepted.\n");

            // Initialize input/output streams
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());
            Scanner input = new Scanner(System.in);

            // Get key
            Path path = Paths.get("DESKeyFile.txt");
            byte[] DESkey = Files.readAllBytes(path);
            SecretKey desKey = new SecretKeySpec(DESkey, 0, DESkey.length, "DES");

            path = Paths.get("HMACKeyFile.txt");
            byte[] hmacKey = Files.readAllBytes(path);
            SecretKey myHmacKey = new SecretKeySpec(hmacKey, 0, hmacKey.length, "HmacSHA256");

            // Initialize decrypter/encryptor
            Cipher DESdecipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            DESdecipher.init(Cipher.DECRYPT_MODE, desKey);

            Cipher DESencipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            DESencipher.init(Cipher.ENCRYPT_MODE, desKey);

            // Initialize HMAC
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(myHmacKey);

            String decLine = "";
            String sentLine = "";
            String msg = "";
            byte[] hmac;
            while (!msg.equals("Over") || !sentLine.equals("Over")) {
                try {
                    int length = in.readInt();

                    if(length > 0) {
                        System.out.println("\nClient message");
                        // Get message bytes
                        byte[] message = new byte[length];
                        in.readFully(message, 0, message.length);

                        // Decrypt it
                        //byte[] hmacBytes = decipher.doFinal(message);
                        byte[] decBytes = DESdecipher.doFinal(message);
                        decLine = new String(decBytes);

                        // Retrieve message and digest
                        msg = decLine.substring(0, decLine.length() - 64);
                        String digest = decLine.substring(decLine.length() - 64);

                        // Perform own hmac for verification
                        hmac = mac.doFinal(msg.getBytes());
                        String hmacString = toHexString(hmac);

                        System.out.println("********************");
                        System.out.println("Recieved ciphertext: " + new String(message));
                        System.out.println("DES Key: " + toHexString(DESkey));
                        System.out.println("HMAC Key: " + toHexString(hmacKey));
                        System.out.println("Received HMAC: " + digest);
                        System.out.println("Decrypted: " + msg);

                        // HMAC Verification
                        if (digest.equals(hmacString)) {
                            System.out.println("HMAC VERIFIED");
                        }

                        System.out.println("********************");

                        if (msg.equals("Over")) {
                            System.exit(0);
                        }

                        // Server responds
                        System.out.print("\nEnter response (Type 'Over' to stop): ");
                        sentLine = input.nextLine();

                        // Encrypt message
                        hmac = mac.doFinal(sentLine.getBytes());
                        String hmacLine = sentLine + toHexString(hmac);
                        byte[] encLine = DESencipher.doFinal(hmacLine.getBytes());

                        System.out.println("********************");
                        System.out.println("Plaintext: " + sentLine);
                        System.out.println("Shared DES Key: " + toHexString(DESkey));
                        System.out.println("Shared HMAC Key: " + toHexString(hmacKey));
                        System.out.println("Sender Side HMAC: " + toHexString(hmac));
                        System.out.println("Sent Ciphertext: " + new String(encLine));
                        System.out.println("********************");

                        // Send to client
                        out.writeInt(encLine.length);
                        out.write(encLine);
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
            System.out.println("Closing connection.");

            socket.close();
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {
        // write your code here
        Server server = new Server(5000);
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
