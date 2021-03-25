package org.example.cmac;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.List;

/**
 * @des aes工具类
 * @author: Nights
 * @date: 2021-03-18
 */
public class AESUtils {

    //偏移量
    public static byte[] iv = DatatypeConverter.parseHexBinary("00000000000000000000000000000000");

    public static String subIV = "00000000000000000000000000000000";

    //加密   key 16byte iv 16byte
    public static String encrypt(String content,String key) throws Exception {
        byte[] raw=hexStringToByte(key);
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        //"算法/模式/补码方式"
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        //CBC模式 添加iv偏移量，增加算法强度，
        IvParameterSpec ips = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ips);
        byte[] encrypted = cipher.doFinal(hexStringToByte(content));
        return bytesToHexString(encrypted);
    }

    //解密
    public static String decrypt(String content,String key) throws Exception {
        try {
            byte[] raw=hexStringToByte(key);
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            IvParameterSpec ips = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ips);
            byte[] encrypted1 = hexStringToByte(content);
            try {
                byte[] original = cipher.doFinal(encrypted1);
                return bytesToHexString(original);
            } catch (Exception e) {
                return null;
            }
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * @des Subkey Generation
     * @param key
     * @return
     * @throws Exception
     */
    public static List<String> createSubKey(String key) throws Exception {
        String hexStrK1,hexStrK2;
        String encrypt = encrypt(subIV, key);
        String binStr=hexToBin(encrypt);
        ArrayList<String> subKeys = new ArrayList<>();
        if (binStr.charAt(0)=='0'){
            //byte[] bytes1 = string2bytes(format(binStr.substring(1) + '0'));
            byte[] bytes1 = string2bytes(binStr.substring(1) + '0');
            hexStrK1=bytesToHexString(bytes1);
        }else{
            //byte[] bytes2 = string2bytes(format(binStr.substring(1) + '0'));
            byte[] bytes2 = string2bytes(binStr.substring(1) + '0');
            byte[] bytes1 = new byte[bytes2.length];
            for (int i = 0; i < bytes2.length; i++) {
                if (i==bytes2.length-1){
                    bytes1[i] = (byte)(bytes2[i] ^ -121);
                }else {
                    bytes1[i]=(byte)(bytes2[i] ^ 0);
                }
            }
            hexStrK1=bytesToHexString(bytes1);
        }
        binStr=hexToBin(hexStrK1);
        if (binStr.charAt(0)=='0'){
            byte[] bytes1 = string2bytes(binStr.substring(1) + '0');
            hexStrK2=bytesToHexString(bytes1);
        }else {
            byte[] bytes2 = string2bytes(binStr.substring(1) + '0');
            byte[] bytes1 = new byte[bytes2.length];
            for (int i = 0; i < bytes2.length; i++) {
                if (i==bytes2.length-1){
                    bytes1[i] = (byte)(bytes2[i] ^ -121);
                }else {
                    bytes1[i]=(byte)(bytes2[i] ^ 0);
                }
            }
            hexStrK2=bytesToHexString(bytes1);
        }
        subKeys.add(hexStrK1);
        subKeys.add(hexStrK2);
        return  subKeys;
    }

    //MAC Generation
    public static String compute(String hexM,String key,int h) throws Exception {
        int  lastBlen = hexM.length()%32;
        int nBlocks=lastBlen==0?hexM.length()/32:hexM.length()/32+1;
        List<String> listM = new ArrayList<>();
        List<String> subKey = createSubKey(key);
        byte[] bytesKey1 = hexStringToByte(subKey.get(0));
        byte[] bytesKey2 = hexStringToByte(subKey.get(1));
        for (int i = 0; i < nBlocks-1; i++) {
            listM.add(hexM.substring(i*32,(i+1)*32));
        }
        if (nBlocks==0&&lastBlen==0){
            String Mn="1";
            for (int i = 0; i < 127; i++) {
                Mn=Mn+"0";
            }
            byte[] bytes = string2bytes(Mn);
            byte[] bytes1 = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                bytes1[i]=(byte)(bytes[i]^bytesKey2[i]);
            }
            listM.add(bytesToHexString(bytes1));
        }else {
            if (lastBlen==0){
                byte[] bytes = hexStringToByte(hexM.substring((nBlocks - 1) * 32));
                byte[] bytes1 = new byte[bytes.length];
                for (int i = 0; i < bytes.length; i++) {
                    bytes1[i]=(byte)(bytes[i] ^ bytesKey1[i]);
                }
                listM.add(bytesToHexString(bytes1));
            }else{
                String Mn = hexToBin(hexM.substring((nBlocks-1) * 32))+"1";
                int j=nBlocks*128-hexM.length()*4-1;
                for (int i = 0; i < j; i++) {
                    Mn=Mn+"0";
                }
                byte[] bytes = string2bytes(Mn);
                byte[] bytes1 = new byte[bytes.length];
                for (int i = 0; i < bytes.length; i++) {
                    bytes1[i]=(byte)(bytes[i]^bytesKey2[i]);
                }
                listM.add(bytesToHexString(bytes1));
            }
        }
        byte[] cipherStep = DatatypeConverter.parseHexBinary("00000000000000000000000000000000");
        for (int i = 0; i < listM.size(); i++) {
            byte[] bytes = hexStringToByte(listM.get(i));
            byte[] bytes1 = new byte[bytes.length];
            for (int j = 0; j < bytes.length; j++) {
                bytes1[j]=(byte)(cipherStep[j]^bytes[j]);
            }
            cipherStep=hexStringToByte(encrypt(bytesToHexString(bytes1), key));
        }
        return bytesToHexString(cipherStep).substring(0,h/4);

    }

    /**
     * @des 16进制转二进制串
     * @param hex
     * @return
     */
    public static String hexToBin(String hex){
        String bin = "";
        String binFragment = "";
        int iHex;
        hex = hex.trim();
        hex = hex.replaceFirst("0x", "");

        for(int i = 0; i < hex.length(); i++){
            iHex = Integer.parseInt(""+hex.charAt(i),16);
            binFragment = Integer.toBinaryString(iHex);

            while(binFragment.length() < 4){
                binFragment = "0" + binFragment;
            }
            bin += binFragment;
        }
        return bin;
    }

    /**
     * @des 二进制转16进制字符串
     * @param src
     * @return
     */
    public static String bytesToHexString(byte[] src){
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    /**
     * @des 16进制转二进制byte
     * @param hex
     * @return
     */
    public static byte[] hexStringToByte(String hex) {
        int len = (hex.length() / 2);
        byte[] result = new byte[len];
        char[] achar = hex.toCharArray();
        for (int i = 0; i < len; i++) {
            int pos = i * 2;
            result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
        }
        return result;
    }
    private static byte toByte(char c) {
        byte b = (byte) "0123456789abcdef".indexOf(c);
        return b;
    }

    /**
     * @des 将01字符串的长度增长为8的倍数，不足部分在末尾追回‘0’。
     * @param input
     * @return
     */
    static String format(String input) {
        int remainder = input.length() % 8;
        StringBuilder sb = new StringBuilder();
        if (remainder > 0) {
            for (int i = 0; i < 8 - remainder; i++)
                sb.append("0");
            sb.append(input);
        }else
            sb.append(input);
        return sb.toString();
    }

    /**
     * @des 二进制字符串转字节数组
     * @param input 输入字符串。
     * @return 转换好的字节数组。
     */
    static byte[] string2bytes(String input) {
        StringBuilder in = new StringBuilder(input);
        int remainder = in.length() % 8;
        if (remainder > 0)
            for (int i = 0; i < 8 - remainder; i++)
                in.append("0");
        byte[] bts = new byte[in.length() / 8];
        //compression
        for (int i = 0; i < bts.length; i++)
            bts[i] = (byte) Integer.parseInt(in.substring(i * 8, i * 8 + 8), 2);
        return bts;
    }


}
