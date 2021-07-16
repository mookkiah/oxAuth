package org.gluu.oxauth.ping;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.util.Base64Util;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

    private static Logger logger = LoggerFactory.getLogger(Utils.class);

    public static final SignatureAlgorithm HS256_ALG = SignatureAlgorithm.HS256;
    public static final String HMAC_SHA256_ALG_NAME = "HmacSHA256";

    public static ResteasyClient rsClient;

    static {
        PoolingHttpClientConnectionManager manager = new PoolingHttpClientConnectionManager();
        manager.setMaxTotal(200);
        manager.setDefaultMaxPerRoute(20);

        RequestConfig config = RequestConfig.custom().setConnectTimeout(10 * 1000).build();
        HttpClient httpClient = HttpClientBuilder.create().setDefaultRequestConfig(config)
                .setConnectionManager(manager).build();
        ApacheHttpClient4Engine engine = new ApacheHttpClient4Engine(httpClient);
        String proxyHost = System.getProperty("https.proxyHost");
        String proxyPort = System.getProperty("https.proxyPort");
        logger.info("proxy {}:{}", proxyHost, proxyPort);
        if (StringUtils.isNotEmpty(proxyHost) && StringUtils.isNoneEmpty(proxyPort)) {
            //TODO proxy authentication?
            logger.info("Using proxy {}:{}", proxyHost, proxyPort);
            rsClient =
                    new ResteasyClientBuilder().defaultProxy(proxyHost,
                            Integer.valueOf(proxyPort)).httpEngine(engine).build();
            logger.info("Rest Client Properties map: {}",
                    rsClient.getConfiguration().getProperties());
        } else {
            rsClient =
                    new ResteasyClientBuilder().httpEngine(engine).build();
        }

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
        try {
            ResteasyWebTarget target = rsClient.target(endpoint);
            logger.info("Sending payload of {} bytes to {}", payload.getBytes().length, endpoint);
            logger.info("{}", payload);

            Response response = target.request().post(Entity.json(payload));
            status = response.getStatus();
            logger.info("Response code was {}", status);
            response.bufferEntity();
            data = response.readEntity(String.class);

            if (status == 200) {
                logger.info("Response body:\n{}", data);
                return data;
            }
            logger.error("Response body:\n{}", data);
            throw new HttpException(status, "Unsuccessful response obtained");
        }catch (Throwable t) { // Ugly - Required because somewhere exception
            // (ClientTimeoutException) suppressed.
            t.printStackTrace();
            throw t;
        }

    }

}
