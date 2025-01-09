import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.CancellationException;

public class Main {

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {

            PrintTitle();

            String algorithm = getAlgorithm(scanner);

            File file = getFile(scanner);

            SecretKey secretKey = generateKey(algorithm);
            String keyBase64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            System.out.println("Generated Key (Base64): " + keyBase64);

            if (file.isDirectory()) {
                encryptFilesRecursively(secretKey, file, algorithm);
            } else {
                encryptFile(secretKey, file, algorithm);
            }

            System.out.println("Generated Key (Base64): " + keyBase64);
            System.out.println("Encryption completed successfully.");

        } catch (IllegalArgumentException e) {
            System.out.println("Invalid algorithm choice.");
        } catch (CancellationException | FileNotFoundException e) {
            System.out.println(e.getMessage());
        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }

    private static File getFile(Scanner scanner) throws Exception {
        System.out.println("Enter the path of the directory or file to encrypt: ");
        String filePath = scanner.nextLine().trim();

        if (filePath.toLowerCase().startsWith("c:")) {
            System.out.println("You are about to encrypt a file in the C: drive. Are you sure you want to continue? (Y/N)");
            String choice = scanner.nextLine();
            if (!choice.equalsIgnoreCase("Y")) {
                System.out.println("Encryption aborted.");
                throw new CancellationException("Encryption aborted.");
            }
        }

        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("Invalid file or directory path.");
        }
        return file;
    }

    private static String getAlgorithm(Scanner scanner) {
        System.out.println("1. AES");
        System.out.println("2. Blowfish");
        System.out.println("Choose an encryption algorithm: ");

        int algoChoice = scanner.nextInt();
        scanner.nextLine();
        return switch (algoChoice) {
            case 1 -> "AES";
            case 2 -> "Blowfish";
            default -> throw new IllegalArgumentException("Invalid choice for algorithm.");
        };
    }

    private static SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(256, new SecureRandom());
        return keyGenerator.generateKey();
    }

    private static void encryptFilesRecursively(SecretKey secretKey, File directory, String algorithm) throws Exception {
        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                encryptFilesRecursively(secretKey, file, algorithm);
            } else {
                encryptFile(secretKey, file, algorithm);
            }
        }
    }

    private static void encryptFile(SecretKey secretKey, File file, String algorithm) throws Exception {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);
        Files.write(file.toPath(), encryptedBytes);
        System.out.println("(¬‿¬) Encrypted file: " + file.getAbsolutePath());
    }

    private static void PrintTitle(){
        System.out.println();
        System.out.println("""
                
                _____________________________  ________________________.___._____________________
                \\______   \\_   _____/\\______ \\ \\_   ___ \\______   \\__  |   |\\______   \\__    ___/
                 |       _/|    __)_  |    |  \\/    \\  \\/|       _//   |   | |     ___/ |    |  \s
                 |    |   \\|        \\ |    `   \\     \\___|    |   \\\\____   | |    |     |    |  \s
                 |____|_  /_______  //_______  /\\______  /____|_  // ______| |____|     |____|  \s
                        \\/        \\/         \\/        \\/       \\/ \\/                           \s
                
                """);
        System.out.println();
        System.out.println(" * Welcome to REDCRYPT - The file encryption / decryption tool.");
        System.out.println(" * This tool uses AES, DES, or Blowfish encryption algorithms to encrypt and decrypt files.");
        System.out.println(" * This tool is for educational purposes only. Do not use it for malicious purposes.");
        System.out.println();
    }
}
