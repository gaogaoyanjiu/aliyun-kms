package Aliyun.KMS;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.exceptions.ServerException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.*;
import java.security.SecureRandom;

/**
 * 测试 KMS
 * 阿里云的密钥管理服务
 */
public class KMSSample {
    
    /**
     * 所在地域ID
     */
//    private static String REGION_ID = "填入您的密钥所在地域ID";
    private static String REGION_ID = "cn-shanghai";
    
    // AccessKey ID和AccessKey Secret是您访问阿里云API的密钥，具有该账户完全的权限，请您妥善保管。
    /**
     * Access Key ID
     */
    private static String ACCESSKEY_ID = "********";
//    private static String ACCESSKEY_ID = "填入您的Access Key ID";
    
    /**
     * Access Key Secret
     */
    private static String ACCESSKEY_SECRET = "********";
//    private static String ACCESSKEY_SECRET = "填入您的Access Key Secret";
    
    /**
     * 加密方法
     * @return 加密文本
     * @paramkeyId 密钥ID
     * @paramplainText 明文
     */
    private static String kmsEncrypt(String keyId, String plainText) {
        IClientProfile profile = DefaultProfile.getProfile(REGION_ID, ACCESSKEY_ID, ACCESSKEY_SECRET);
        DefaultAcsClient client = new DefaultAcsClient(profile);
        String cipherBlob = "";
        try {
            final EncryptRequest encReq = new EncryptRequest();
            encReq.setProtocol(ProtocolType.HTTPS);
            encReq.setAcceptFormat(FormatType.JSON);
            encReq.setMethod(MethodType.POST);
            encReq.setKeyId(keyId);
            encReq.setPlaintext(plainText);
            final EncryptResponse encResponse = client.getAcsResponse(encReq);
            cipherBlob = encResponse.getCiphertextBlob();
        } catch (ClientException eResponse) {
            eResponse.printStackTrace();
        }
        return cipherBlob;
    }
    
    /**
     * 获取数据密钥
     * @param keyId
     * @param keyDesc
     * @param encryptionContext
     * @return
     */
    private static GenerateDataKeyResponse kmsGenerateDataKey(String keyId, String keyDesc, String encryptionContext) {
        IClientProfile profile = DefaultProfile.getProfile(REGION_ID, ACCESSKEY_ID, ACCESSKEY_SECRET);
        DefaultAcsClient kmsClient = new DefaultAcsClient(profile);
        final GenerateDataKeyRequest genDKReq = new GenerateDataKeyRequest();
        genDKReq.setProtocol(ProtocolType.HTTPS);
        genDKReq.setAcceptFormat(FormatType.JSON);
        genDKReq.setMethod(MethodType.POST);
        genDKReq.setKeySpec(keyDesc);
        genDKReq.setKeyId(keyId);
        // genDKReq.setNumberOfBytes(numOfBytes);
        if (!"".equals(encryptionContext)) {
            genDKReq.setEncryptionContext(encryptionContext);
        }
        GenerateDataKeyResponse genDKRes = null;
        try {
            genDKRes = kmsClient.getAcsResponse(genDKReq);
        } catch (ServerException e) {
            e.printStackTrace();
        } catch (ClientException e) {
            e.printStackTrace();
        }
        return genDKRes;
    }
    
    /**
     *  解密方法
     * @param cipherBlob
     * @param encryptionContext
     * @return
     */
    private static DecryptResponse kmsDecrypt(String cipherBlob, String encryptionContext) {
        IClientProfile profile = DefaultProfile.getProfile(REGION_ID, ACCESSKEY_ID, ACCESSKEY_SECRET);
        DefaultAcsClient kmsClient = new DefaultAcsClient(profile);
        final DecryptRequest decReq = new DecryptRequest();
        decReq.setProtocol(ProtocolType.HTTPS);
        decReq.setAcceptFormat(FormatType.JSON);
        decReq.setMethod(MethodType.POST);
        decReq.setCiphertextBlob(cipherBlob);
        if (!"".equals(encryptionContext)) {
            decReq.setEncryptionContext(encryptionContext);
        }
        DecryptResponse decResponse = null;
        try {
            decResponse = kmsClient.getAcsResponse(decReq);
        } catch (ServerException e) {
            e.printStackTrace();
        } catch (ClientException e) {
            e.printStackTrace();
        }
        return decResponse;
    }
    
    /**
     *  調用自己的解密方法
     * @param cipherBlob
     * @return
     */
    private static String kmsDecrypt(String cipherBlob) {
        String plainText = kmsDecrypt(cipherBlob, "").getPlaintext();
        return plainText;
    }
    
    /**
     * base64编码
     * @param source
     * @return
     */
    private static String base64encode(byte[] source) {
        return new String(new Base64().encode(source));
    }
    
    /**
     * base64解码
     * @param source
     * @return
     */
    private static byte[] base64decode(String source) {
        try {
            return (new Base64().decode(source.getBytes("utf-8")));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * DES加密
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    private static String desEncrypt(String data, String key) {
        String strs = "";
        try {
            byte[] databt = data.getBytes("utf-8");
            byte[] keybt = key.getBytes("utf-8");
            // 生成一个可信任的随机数源
            SecureRandom sr = new SecureRandom();
            // 从原始密钥数据创建DESKeySpec对象
            DESKeySpec dks = new DESKeySpec(keybt);
            // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = keyFactory.generateSecret(dks);
            // Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("DES");
            // 用密钥初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);
            strs = base64encode(cipher.doFinal(databt));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strs;
    }
    
    /**
     * DES解密
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    private static String desDecrypt(String data, String key) {
        String strs = "";
        try {
            byte[] databt = base64decode(data);
            byte[] keybt = key.getBytes("utf-8");
            // 生成一个可信任的随机数源
            SecureRandom sr = new SecureRandom();
            // 从原始密钥数据创建DESKeySpec对象
            DESKeySpec dks = new DESKeySpec(keybt);
            // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = keyFactory.generateSecret(dks);
            // Cipher对象实际完成解密操作
            Cipher cipher = Cipher.getInstance("DES");
            // 用密钥初始化Cipher对象
            cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
            byte[] bt = cipher.doFinal(databt);
            strs = new String(bt, "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strs;
    }
    
    /**
     * 写文件
     * @param file
     * @param content
     */
    private static void writeFile(File file, String content) {
        try {
            if (!file.exists()) {
                file.createNewFile(); // 创建文件
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte bt[] = new byte[1024];
        bt = content.getBytes();
        try {
            FileOutputStream in = new FileOutputStream(file);// 向文件写入内容(输出流)
            try {
                in.write(bt, 0, bt.length);
                in.close();
                // System.out.println("写入文件成功");
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * 读文件
     * @param file
     * @return
     */
    private static String readFile(File file) {
        String content = "";
        InputStreamReader isr = null;
        try {
            FileInputStream out = new FileInputStream(file);// 读取文件内容(输入源)
            isr = new InputStreamReader(out);
            int ch = 0;
            while ((ch = isr.read()) != -1) {
                // System.out.print((char) ch);
                content += (char) ch;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return content;
    }
    
    public static void main(String[] args) {
        // 加解密方法测试
        String keyId = "********";  // 必须和 所在地域ID在同一个区域
//        String keyId = "填入您的密钥ID";
        String plainText = "Hello,KMS";
        String encryptText = kmsEncrypt(keyId, plainText);
        System.out.println("输出加密文本: " + encryptText);
        String decryptText = kmsDecrypt(encryptText);
        System.out.println("输出解密文本: " + decryptText);

        // 直接加解密配置文件信息测试
        String writeFileContent = ""; // 初始变量
        String readFileContent = "";  // 初始变量
        plainText = "user.defaultPassword=Aliyun2017!";
        File file = new File("c:/temp", "core.properties");
        writeFileContent = base64encode(kmsEncrypt(keyId, plainText).getBytes());
        writeFile(file, writeFileContent);
        System.out.println("\n输出加密配置文件信息1：" + writeFileContent);
        readFileContent = readFile(file);
        System.out.println("输出解密配置文件信息1：" + kmsDecrypt(new String(base64decode(readFileContent))));

        // 数字信封加解密配置文件信息测试
        String encryptionContext = "{\"date\":\"20181212\"}";
//        String encryptionContext = "{\"date\":\"20171001\"}";
        GenerateDataKeyResponse genDKResponse = kmsGenerateDataKey(keyId, "AES_128", encryptionContext);
        String dataKeyCipher = genDKResponse.getCiphertextBlob();
        String dataKeyPlain = genDKResponse.getPlaintext();
        writeFileContent = desEncrypt(plainText, dataKeyPlain);
        writeFile(file, writeFileContent);
        System.out.println("\n输出加密配置文件信息2：" + writeFileContent);
        readFileContent = readFile(file);
        String dataKeyPlainText = kmsDecrypt(dataKeyCipher, encryptionContext).getPlaintext();
        System.out.println("输出解密配置文件信息2：" + desDecrypt(readFileContent, dataKeyPlainText));
    }
}
