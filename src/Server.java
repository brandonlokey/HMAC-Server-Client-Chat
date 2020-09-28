import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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
            Cipher decipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, desKey);

            Cipher ecipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            ecipher.init(Cipher.ENCRYPT_MODE, desKey);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(myHmacKey);

            String decLine = "";
            String sentLine = "";

            while (!decLine.equals("Over") || !sentLine.equals("Over")) {
                try {
                    int length = in.readInt();

                    if(length > 0) {
                        System.out.println("\nClient message");
                        // Get message bytes
                        byte[] message = new byte[length];
                        in.readFully(message, 0, message.length);

                        // Decrypt it
                        byte[] hmacBytes = decipher.doFinal(message);
                        byte[] decBytes = mac.doFinal(hmacBytes);
                        decLine = new String(decBytes);

                        System.out.println("********************");
                        System.out.println("Encrypted: " + new String(message));
                        System.out.println("DES Key: " + DESkey);
                        System.out.println("HMAC Key: " + hmacKey);
                        System.out.println("Received HMAC: " + new String(hmacBytes));
                        System.out.println("Decrypted: " + decLine);
                        System.out.println("********************");

                        if (decLine.equals("Over")) {
                            System.exit(0);
                        }

                        // Server responds
                        System.out.print("\nEnter response (Type 'Over' to stop): ");
                        sentLine = input.nextLine();

                        // Encrypt message
                        byte[] encLine = ecipher.doFinal(sentLine.getBytes());

                        System.out.println("********************");
                        System.out.println("Plaintext: " + sentLine);
                        System.out.println("Key: " + DESkey);
                        System.out.println("Encrypted: " + new String(encLine));
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
}
