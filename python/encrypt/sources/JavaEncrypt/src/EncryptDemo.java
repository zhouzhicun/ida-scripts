import java.io.IOException;

public class EncryptDemo {


    public static void test_sha1() throws Exception {

        String testText = "admin";

        System.out.println("SHA1测试结果 ==>");
        System.out.println("testText = " + testText);
        System.out.println("sha1: " + SHA1.generate(testText.getBytes()));
    }


    public static void test_sha256() {

        String testText = "admin";

        System.out.println("SHA256测试结果 ==>");
        System.out.println("testText = " + testText);
        System.out.println("sha256: " + Utils.bytesToHexStr(SHA256.hash(testText.getBytes())));
    }


    public static void test_md5() {

        String testText = "admin";

        System.out.println("md5测试结果 ==>");
        System.out.println("testText = " + testText);

        MD5 md = new MD5();
        System.out.println("md5: " + md.digest(testText));

    }

    public static void test_sm3() throws IOException {

        String testText = "admin";

        System.out.println("sm3测试结果 ==>");
        System.out.println("testText = " + testText);

        byte[] resultBytes = SM3.hash(testText.getBytes());
        System.out.println("sm3: " + Utils.bytesToHexStr(resultBytes));

    }

    public static void test_sm4() throws IOException {

        // key必须是16位
        String key = "1234567812345678";
        String testText = "1234567812345678";

        System.out.println("sm4测试结果 ==>");
        System.out.println("testText = " + testText);

        SM4 sm4 = new SM4(key.getBytes());
        byte[] cipherTextBytes = sm4.encrypt(testText.getBytes());
        System.out.println("sm4: " + Utils.bytesToHexStr(cipherTextBytes));

    }


    public static void main(String[] args) throws Exception {
        test_sha1();
        test_sha256();
        test_md5();
        test_sm3();
        test_sm4();
    }

}
