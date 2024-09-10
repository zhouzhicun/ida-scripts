//import com.github.unidbg.utils.Inspector;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class SM4 {

    int[] key_r;

    /* 初始化轮密钥 */
    SM4(byte[] key) {
        this.key_r = keyGenerate(key);
    }

    /* 密钥拓展 */
    private int[] keyGenerate(byte[] key) {
        int[] key_r = new int[32];//轮密钥rk_i
        int[] key_temp = new int[4];
        int box_in, box_out;//盒变换输入输出
        final int[] FK = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
        final int[] CK = {
                0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
                0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
                0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
                0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        };
        //将输入的密钥每32比特合并，并异或FK
        for (int i = 0; i < 4; i++) {
            key_temp[i] = jointBytes(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
            key_temp[i] = key_temp[i] ^ FK[i];
        }
        //32轮密钥拓展
        for (int i = 0; i < 32; i++) {
            box_in = key_temp[1] ^ key_temp[2] ^ key_temp[3] ^ CK[i];
            box_out = sBox(box_in);
            key_r[i] = key_temp[0] ^ box_out ^ shift(box_out, 13) ^ shift(box_out, 23);
            key_temp[0] = key_temp[1];
            key_temp[1] = key_temp[2];
            key_temp[2] = key_temp[3];
            key_temp[3] = key_r[i];
        }
        return key_r;
    }

    /* 加解密主模块 */
    private static byte[] sm4Main(byte[] input, int[] key_r, int mod) {
        int[] text = new int[4];//32比特字
        //将输入以32比特分组
        for (int i = 0; i < 4; i++) {
            text[i] = jointBytes(input[4 * i], input[4 * i + 1], input[4 * i + 2], input[4 * i + 3]);
        }
        int box_input, box_output;//盒变换输入和输出
        for (int i = 0; i < 32; i++) {
            int index = (mod == 0) ? i : (31 - i);//通过改变key_r的顺序改变模式
            box_input = text[1] ^ text[2] ^ text[3] ^ key_r[index];
            box_output = sBox(box_input);
            int temp = text[0] ^ box_output ^ shift(box_output, 2) ^ shift(box_output, 10) ^ shift(box_output, 18) ^ shift(box_output, 24);
            text[0] = text[1];
            text[1] = text[2];
            text[2] = text[3];
            text[3] = temp;
        }
        byte[] output = new byte[16];//输出
        //将结果的32比特字拆分
        for (int i = 0; i < 4; i++) {
            System.arraycopy(splitInt(text[3 - i]), 0, output, 4 * i, 4);
        }
        return output;
    }

    /* 加密 */
    public byte[] encrypt(byte[] plaintext) {
        return sm4Main(plaintext, key_r, 0);
    }

    /* 解密 */
    public byte[] decrypt(byte[] ciphertext) {
        return sm4Main(ciphertext, key_r, 1);
    }

    /* 将32比特数拆分成4个8比特数 */
    private static byte[] splitInt(int n) {
        return new byte[]{(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n};
    }

    /* 将4个8比特数合并成32比特数 */
    private static int jointBytes(byte byte_0, byte byte_1, byte byte_2, byte byte_3) {
        return ((byte_0 & 0xFF) << 24) | ((byte_1 & 0xFF) << 16) | ((byte_2 & 0xFF) << 8) | (byte_3 & 0xFF);
    }
    
    /* S盒变换 */
    private static int sBox(int box_input) {
        //s盒的参数
        final int[] SBOX = {
                0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A,
                0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF,
                0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62, 0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80,
                0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19,
                0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D,
                0x35, 0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87, 0xD4, 0x00,
                0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2, 0x40,
                0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1, 0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
                0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23,
                0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C,
                0x5B, 0x51, 0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8, 0x0A,
                0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
                0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84, 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D,
                0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
        };

        byte[] temp = splitInt(box_input);//拆分32比特数
        byte[] output = new byte[4];//单个盒变换输出
        //盒变换
        for (int i = 0; i < 4; i++) {
            output[i] = (byte) SBOX[temp[i] & 0xFF];
        }
        //将4个8位字节合并为一个字作为盒变换输出
        return jointBytes(output[0], output[1], output[2], output[3]);
    }

    /* 将input左移n位 */
    private static int shift(int input, int n) {
        return (input >>> (32 - n)) | (input << n);
    }

    public static void main(String[] args) {
        // key必须是16位
        byte[] key = "1234567812345678".getBytes();
        byte[] plaintext = "1234567812345678".getBytes();

        SM4 sm4_t = new SM4(key);
        byte[] ciphertext_t = sm4_t.encrypt(plaintext);
        //System.out.println("自己写的函数加密结果\t" + Inspector.inspectString(ciphertext_t, ""));
        System.out.println("自己写的函数加密结果\n" + Utils.bytesToHexStr(ciphertext_t));
    }
}