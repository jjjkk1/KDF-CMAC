package org.example.cmac;

import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * @author: Nights
 * @date: 2021-03-18
 */
public class AesTest {

    /**
     * K 2b7e1516 28aed2a6 abf71588 09cf4f3c
     */

    /**
     * Subkey Generation
     * CIPHK(0128) 7df76b0c 1ab899b3 3e42f047 b91b546f
     * K1 fbeed618 35713366 7c85e08f 7236a8de
     * K2 f7ddac30 6ae266cc f90bc11e e46d513b
     * @des aes128 encrypt/decrypt;subKey generate
     */
    @Test
    public void test() throws Exception {
        String encrypt = AESUtils.encrypt(AESUtils.subIV, "2b7e151628aed2a6abf7158809cf4f3c");
        System.out.println(encrypt);
        String decrypt = AESUtils.decrypt(encrypt, "2b7e151628aed2a6abf7158809cf4f3c");
        System.out.println(decrypt);
        List<String> subKey = AESUtils.createSubKey("2b7e151628aed2a6abf7158809cf4f3c");
        System.out.println(subKey);
    }

    //kdf test
    @Test
    public void test0() throws Exception {
        String s = KdfAlgUtils.kdfAlg("2b7e151628aed2a6abf7158809cf4f3c", 64, 8, "020202020202020202020202", "F10012F1011001020304050607080102030405060708F20039F2011011113144", "0080");
        System.out.println(s);
    }

    /**
     * Example : Mlen = 128
     * M 6bc1bee2 2e409f96 e93d7e11 7393172a
     * T 070a16b4 6b4d4144 f79bdd9d d04a287c
     */
    @Test
    public void test1() throws Exception {
        String compute = AESUtils.compute("6bc1bee22e409f96e93d7e117393172a", "2b7e151628aed2a6abf7158809cf4f3c", 128);
        System.out.println(compute);
    }

    /**
     * Example : Mlen = 320
     * M 6bc1bee2 2e409f96 e93d7e11 7393172a
     *   ae2d8a57 1e03ac9c 9eb76fac 45af8e51
     *   30c81c46 a35ce411
     * T dfa66747 de9ae630 30ca3261 1497c827
     */
    @Test
    public void test2() throws Exception {
        String compute = AESUtils.compute("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "2b7e151628aed2a6abf7158809cf4f3c", 128);
        System.out.println(compute);
    }

    /**
     * Example : Mlen = 512
     * M 6bc1bee2 2e409f96 e93d7e11 7393172a
     *   ae2d8a57 1e03ac9c 9eb76fac 45af8e51
     *   30c81c46 a35ce411 e5fbc119 1a0a52ef
     *   f69f2445 df4f9b17 ad2b417b e66c3710
     * T 51f0bebf 7e3b9d92 fc497417 79363cfe
     */
    @Test
    public void test3() throws Exception {
        String compute = AESUtils.compute("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "2b7e151628aed2a6abf7158809cf4f3c", 128);
        System.out.println(compute);
    }

    /**
     * Example : Mlen 0
     * M <empty string>
     * T bb1d6929 e9593728 7fa37d12 9b756746
     */
    @Test
    public void test4() throws Exception {
        String compute = AESUtils.compute("", "2b7e151628aed2a6abf7158809cf4f3c", 128);
        System.out.println(compute);
    }
}
