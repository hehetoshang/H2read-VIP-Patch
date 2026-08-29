import java.nio.file.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** 与 App 完全一致的 Java 侧验签交叉验证: 公钥解析 + SHA256withRSA */
public class JavaCompatCheck {
    public static void main(String[] args) throws Exception {
        String pubPem = Files.readString(Path.of(args[0]));
        String lic = Files.readString(Path.of(args[1])).trim();

        String clean = pubPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(clean)));
        System.out.println("PUBKEY OK: " + pub.getAlgorithm() + "/" + ((java.security.interfaces.RSAPublicKey) pub).getModulus().bitLength() + " bits");

        String[] parts = lic.split("\\.");
        byte[] payload = Base64.getDecoder().decode(parts[1]);
        byte[] sig = Base64.getDecoder().decode(parts[2]);

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pub);
        s.update(payload);
        boolean ok = s.verify(sig);
        System.out.println("SHA256withRSA VERIFY: " + (ok ? "OK" : "FAIL"));
        System.exit(ok ? 0 : 1);
    }
}
