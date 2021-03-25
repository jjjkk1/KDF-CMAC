package org.example.cmac;

/**
 * @author: Nights
 * @date: 2021-03-18
 * @des: kdf
 */
public class KdfAlgUtils {

    public static String prf(String key,String content,int h) throws Exception {
        String compute = AESUtils.compute(content, key,h);
        System.out.println(compute);
        return compute;
    }

    //String：hexString
    public static String kdfAlg(String key,int h,int r,String label,String context,String l) throws Exception {
        int L= Integer.parseInt(l, 16);
        int n=L%h==0?L/h:L/h+1;
        if (n>Math.pow(2,r)){
            return null;
        }
        // [i]2 || Label || 0x00 || Context || [L]2
        //content: i 1byte,label 12byte, 0x00,context 32Byte,l 2byte
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < n; i++) {
            System.out.println(i);
            String content = generateContent(i, label, context, l);
            stringBuilder.append(prf(key,content,h));
        }
        //L/8
        return stringBuilder.substring(0,L/4);
    }

    public static String generateContent(int i, String label, String context, String l){
        String count = Integer.toHexString(i);
        StringBuilder content = new StringBuilder();
        if (count.length()>=2){
            count=count.substring(count.length()-2);
        }else {
            count="0"+count;
        }
        content.append(count).append(label).append("00").append(context).append(l);
        return content.toString();
    }
}
