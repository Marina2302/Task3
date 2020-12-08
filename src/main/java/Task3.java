import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class Task3 {
    private static int uMove;
    private static int cMove;

    public static void main(String[] args) {
        if (!checkArg(args)) {
            return;
        }
        cMove = doMove(args);
        String secretMove = encode(generateRandomKey(), args[cMove - 1]);
        showMenu(args);
        checkMove(secretMove, args);
    }

    private static boolean checkArg(String[] args) {
        boolean argsIsCorrect = true;
        if (args.length < 3) {
            System.out.println(args.length + " lines entered. >= 3 strings must be entered. For example: Rock Paper Scissors.");
            argsIsCorrect = false;
        }
        if (args.length % 2 == 0) {
            System.out.println("An even number of lines entered. An odd number of lines must be entered. For example: Rock Paper Scissors.");
            argsIsCorrect = false;
        }
        if (new HashSet<>(Arrays.asList(args)).size() != args.length) {
            System.out.println("Duplicate lines entered. Unique strings must be entered. For example: Rock Paper Scissors.");
            argsIsCorrect = false;
        }
        return argsIsCorrect;
    }

    private static byte[] generateRandomKey() {
        SecureRandom randomKey = new SecureRandom();
        return randomKey.generateSeed(16);
    }

    private static int doMove(String[] args) {
        return new Random().nextInt(args.length) + 1;
    }

    private static String encode(byte[] key, String move) {
        String secretMove = "";
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
            hmac.init(secretKey);
            secretMove = String.valueOf(Hex.encodeHex(secretKey.getEncoded()));
            System.out.println("HMAC:\n" + String.valueOf(Hex.encodeHex(hmac.doFinal(move.getBytes(StandardCharsets.UTF_8)))));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return secretMove;
    }

    private static void showMenu(String[] args) {
        System.out.println("Available moves:");
        int i = 1;
        for (String s : args) {
            System.out.println(i + " - " + s);
            ++i;
        }
        System.out.println("0 - exit");
    }

    private static void checkMove(String secretMove, String[] args) {
        System.out.print("Enter your move: ");
        Scanner sc = new Scanner(System.in);
        try {
            uMove = sc.nextInt();
            if (isMoveNumValid(uMove, args)) {
                if (uMove == 0) {
                    return;
                }
                toFight(secretMove, args);
            } else {
                throw new NumberFormatException();
            }
        } catch (InputMismatchException | NumberFormatException e) {
            showMenu(args);
            checkMove(secretMove, args);
        }
    }

    private static boolean isMoveNumValid(int num, String[] args) {
        return !(num < 0 | num > args.length);
    }

    private static void toFight(String secretMove, String[] args) {
        System.out.println("Your move: " + args[uMove - 1]);
        System.out.println("Computer move: " + args[cMove - 1]);

        int mid = args.length / 2;
        if (cMove == uMove) {
            System.out.println("A draw.");
        } else if (cMove > uMove) {
            if (cMove <= uMove + mid) {
                System.out.println("Computer win!");
            } else {
                System.out.println("You win!");
            }
        } else {
            if (cMove < uMove - mid) {
                System.out.println("Computer win!");
            } else {
                System.out.println("You win!");
            }
        }
        System.out.println("HMAC key: " + secretMove);

    }
}
