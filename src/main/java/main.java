import sun.security.pkcs.*;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class main {

    public static void main(String[] args) {

        String FILENAME = "d:\\f.txt";
        String PASSWORD = "getKeyStorePassword";

        try {
            final byte[] data = "xmlMapper.writeValueAsString(entity)".getBytes();

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream inputStream = new FileInputStream(FILENAME);
            keyStore.load(inputStream, PASSWORD.toCharArray());

            MessageDigest msgDigest = MessageDigest.getInstance("SHA-1");
            PKCS9Attributes p9 = new PKCS9Attributes(
                    new PKCS9Attribute[]{
                            new PKCS9Attribute(PKCS9Attribute.CONTENT_TYPE_OID, ContentInfo.DATA_OID),
                            new PKCS9Attribute(PKCS9Attribute.SIGNING_TIME_OID, new Date()),
                            new PKCS9Attribute(PKCS9Attribute.MESSAGE_DIGEST_OID, msgDigest.digest(data)),
                    });

            X509Certificate cert = (X509Certificate) keyStore.getCertificate("getKeyAlias()");
            PrivateKey key = (PrivateKey) keyStore.getKey("getKeyAlias()", "getKeyStorePassword()".toCharArray());
            Signature sig = Signature.getInstance("SHA512withRSA");
            sig.initSign(key);
            sig.update(p9.getDerEncoding());
            byte[] sigBytes = sig.sign();

            ContentInfo cInfo = new ContentInfo(ContentInfo.DATA_OID, null);

            X500Name name = X500Name.asX500Name(cert.getIssuerX500Principal());
            BigInteger serial = cert.getSerialNumber();
            AlgorithmId dAlgorithm = new AlgorithmId(AlgorithmId.SHA_oid);
            AlgorithmId sAlgorithm = new AlgorithmId(AlgorithmId.RSAEncryption_oid);
            SignerInfo sInfo = new SignerInfo(name, serial, dAlgorithm, p9, sAlgorithm, sigBytes, null);

            PKCS7 p7 = new PKCS7(
                    new AlgorithmId[]{dAlgorithm},
                    cInfo,
                    new X509Certificate[]{cert},
                    new SignerInfo[]{sInfo});

            ByteArrayOutputStream outStream = new DerOutputStream();
            p7.encodeSignedData(outStream);
            byte[] p7Bytes = outStream.toByteArray();
            System.out.println(p7Bytes);
//            return Base64.getEncoder().encodeToString(p7Bytes);

        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }
}

