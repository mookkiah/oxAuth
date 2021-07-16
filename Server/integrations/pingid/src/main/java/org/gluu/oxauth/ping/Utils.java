package org.gluu.oxauth.ping;

import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.util.Base64Util;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Utils {

    private static Logger logger = LoggerFactory.getLogger(Utils.class);

    public static final SignatureAlgorithm HS256_ALG = SignatureAlgorithm.HS256;
    public static final String HMAC_SHA256_ALG_NAME = "HmacSHA256";

    private static HttpClient httpClient;

    static {
        httpClient = HttpClient.newHttpClient();
    }

    public static String generateHS256Signature(String input, byte secret[])
            throws NoSuchAlgorithmException, InvalidKeyException {

        SecretKey secretKey = new SecretKeySpec(secret, HMAC_SHA256_ALG_NAME);
        Mac mac = Mac.getInstance(HMAC_SHA256_ALG_NAME);
        mac.init(secretKey);

        byte[] sig = mac.doFinal(input.getBytes());
        return Base64Util.base64urlencode(sig);

    }

    public static String post(String endpoint, String payload) throws HttpException {

        int status;
        String data;
        var request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .uri(URI.create(endpoint))
                .build();
        try{
            logger.info("HttpClient sending payload of {} bytes to {}", payload.getBytes().length,
                    endpoint);
            logger.info("{}", payload);
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            data = response.body();
            status = response.statusCode();
            logger.info("Response code was {}", status);
            logger.info("Response body:\n{}", data);
            if (status == 200) {
                return data;
            }
            logger.error("Response body:\n{}", data);
            throw new HttpException(status, "Unsuccessful response obtained");
        }catch (InterruptedException | IOException e){
            e.printStackTrace(); // Because somewhere the exception thrown here eaten.
            throw new HttpException("Unsuccessful response obtained", e);
        }




    }

}
