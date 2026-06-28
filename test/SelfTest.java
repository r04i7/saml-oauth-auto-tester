import com.pentest.samloauth.saml.SamlCodec;
import com.pentest.samloauth.saml.SamlMutations;
import com.pentest.samloauth.oauth.JwtUtils;

import java.util.Base64;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/** Standalone checks for the non-Burp core (codec + XML mutations + JWT). */
public class SelfTest {

    static int pass = 0, fail = 0;
    static void check(String label, boolean cond) {
        System.out.printf("  [%s] %s%n", cond ? "PASS" : "FAIL", label);
        if (cond) pass++; else fail++;
    }

    public static void main(String[] args) throws Exception {
        String saml =
            "<?xml version=\"1.0\"?>" +
            "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_resp1\" " +
                "InResponseTo=\"_req9\" Destination=\"https://sp.good.example/acs\">" +
              "<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://idp.good.example/</saml2:Issuer>" +
              "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_assert1\">" +
                "<saml2:Subject><saml2:NameID>user@victim.example</saml2:NameID>" +
                  "<saml2:SubjectConfirmationData Recipient=\"https://sp.good.example/acs\" NotOnOrAfter=\"2020-01-01T00:00:00Z\"/>" +
                "</saml2:Subject>" +
                "<saml2:Conditions NotOnOrAfter=\"2020-01-01T00:00:00Z\">" +
                  "<saml2:AudienceRestriction><saml2:Audience>https://sp.good.example/</saml2:Audience></saml2:AudienceRestriction>" +
                "</saml2:Conditions>" +
                "<saml2:AttributeStatement><saml2:Attribute Name=\"role\">" +
                  "<saml2:AttributeValue>user</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement>" +
                "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
                  "<ds:SignedInfo><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" +
                  "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms></ds:SignedInfo>" +
                  "<ds:SignatureValue>ABCDEF1234567890</ds:SignatureValue>" +
                  "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIORIGINALCERT==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
                "</ds:Signature>" +
              "</saml2:Assertion>" +
            "</saml2p:Response>";

        System.out.println("== POST binding round-trip ==");
        String b64 = Base64.getEncoder().encodeToString(saml.getBytes(StandardCharsets.UTF_8));
        SamlCodec.Decoded d = SamlCodec.decode(b64);
        check("decoded as POST", d != null && d.binding == SamlCodec.Binding.POST);

        System.out.println("== REDIRECT binding round-trip ==");
        String enc = SamlCodec.encode(saml, SamlCodec.Binding.REDIRECT);
        String back = URLDecoder.decode(URLEncoder.encode(enc, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        SamlCodec.Decoded dr = SamlCodec.decode(back);
        check("decoded as REDIRECT (deflate)", dr != null && dr.binding == SamlCodec.Binding.REDIRECT
                && dr.xml.contains("user@victim.example"));

        System.out.println("== signature / identity mutations ==");
        check("stripSignature removes signature", nn(SamlMutations.stripSignature(saml)) && !SamlMutations.stripSignature(saml).contains("SignatureValue"));
        check("emptySignatureValue blanks value", SamlMutations.emptySignatureValue(saml).contains("<ds:SignatureValue></ds:SignatureValue>"));
        check("tamperNameID forges admin", SamlMutations.tamperNameID(saml).contains("admin@victim.example"));
        check("commentInjection inserts comment", SamlMutations.commentInjectionNameID(saml).contains("<!---->"));
        check("tamperIssuer changes issuer", SamlMutations.tamperIssuer(saml).contains("attacker.evil-idp.example"));

        System.out.println("== XSW 1-8 ==");
        check("XSW1 produces output w/ evil id", has(SamlMutations.xsw1(saml), "_xsw1_evil"));
        check("XSW2 produces output w/ evil id", has(SamlMutations.xsw2(saml), "_xsw2_evil"));
        check("XSW3 evil before original", has(SamlMutations.xsw3(saml), "_xsw3_evil") && SamlMutations.xsw3(saml).contains("_assert1"));
        check("XSW4 evil wraps original", has(SamlMutations.xsw4(saml), "_xsw4_evil") && SamlMutations.xsw4(saml).contains("_assert1"));
        check("XSW5 borrows signature", has(SamlMutations.xsw5(saml), "_xsw5_evil"));
        check("XSW6 original in signature", has(SamlMutations.xsw6(saml), "_xsw6_evil"));
        check("XSW7 uses Extensions", has(SamlMutations.xsw7(saml), "Extensions") && has(SamlMutations.xsw7(saml), "_xsw7_evil"));
        check("XSW8 uses Object", has(SamlMutations.xsw8(saml), "Object") && has(SamlMutations.xsw8(saml), "_xsw8_evil"));
        check("XSW forged carries admin identity", has(SamlMutations.xsw3(saml), "admin@victim.example"));

        System.out.println("== conditions / cert / misc ==");
        check("certificateFaking replaces cert", has(SamlMutations.certificateFaking(saml), "AttackerControlled") && !SamlMutations.certificateFaking(saml).contains("MIIORIGINALCERT"));
        check("algo downgrade -> sha1", has(SamlMutations.signatureAlgorithmDowngrade(saml), "rsa-sha1"));
        check("expiry tamper -> 2099", has(SamlMutations.expiryTampering(saml), "2099-01-01"));
        check("audience tamper", has(SamlMutations.audienceTampering(saml), "attacker.evil-sp.example"));
        check("recipient tamper", has(SamlMutations.recipientTampering(saml), "attacker.evil-sp.example/acs"));
        check("attribute role escalation", has(SamlMutations.attributeRoleTampering(saml), "Administrator"));
        check("InResponseTo removed", SamlMutations.inResponseToRemoval(saml) != null && !SamlMutations.inResponseToRemoval(saml).contains("InResponseTo"));
        check("xslt injection added", has(SamlMutations.xsltInjection(saml), "xsl:stylesheet"));
        check("xxe adds DOCTYPE+entity", has(SamlMutations.xxeInjection(saml), "<!DOCTYPE") && has(SamlMutations.xxeInjection(saml), "&xxe;"));

        System.out.println("== not-applicable handling ==");
        String noSig = "<Response><Assertion><Subject><NameID>a@b.c</NameID></Subject></Assertion></Response>";
        check("stripSignature null when no signature", SamlMutations.stripSignature(noSig) == null);
        check("certificateFaking null when no cert", SamlMutations.certificateFaking(noSig) == null);
        check("tamperNameID works without prefix", has(SamlMutations.tamperNameID(noSig), "admin@b.c"));

        System.out.println("== JWT (OIDC id_token) ==");
        String header = b64url("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        String payload = b64url("{\"sub\":\"user\",\"email\":\"user@victim.example\",\"role\":\"user\"}");
        String jwt = header + "." + payload + ".AAAAsignatureBBBB";
        check("looksLikeJwt true", JwtUtils.looksLikeJwt(jwt));
        String none = JwtUtils.algNone(jwt);
        check("algNone sets none + empty sig", none != null && none.endsWith(".") && new String(Base64.getUrlDecoder().decode(none.split("\\.")[0])).contains("none"));
        String strip = JwtUtils.stripSignature(jwt);
        check("stripSignature blanks sig", strip != null && strip.endsWith(".") && strip.startsWith(header + "." + payload));
        String esc = JwtUtils.escalateClaims(jwt);
        String escPayload = new String(Base64.getUrlDecoder().decode(pad(esc.split("\\.")[1])));
        check("escalateClaims -> admin", escPayload.contains("admin"));

        System.out.println("\nRESULT: " + pass + " passed, " + fail + " failed.");
        if (fail > 0) System.exit(1);
    }

    static boolean nn(String s){ return s != null; }
    static boolean has(String s, String needle){ return s != null && s.contains(needle); }
    static String b64url(String s){ return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8)); }
    static String pad(String s){ int m=s.length()%4; return m==0?s:s+"====".substring(m); }
}
