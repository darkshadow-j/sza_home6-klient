package pl.plenczewski.jwttokenclinet.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sun.org.apache.bcel.internal.generic.ARETURN;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Service
public class ClientAPI {

    private String priv = "MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQC13iID7Fl8WoNP\n" +
            "bnlTADvU/RCLtQBd+RB3FY4q5C9C5JeBGDE9X4dTBc/0Nwusyq10VP9bNprneTYJ\n" +
            "0qN7qx4Y1/NsabSmdiBSRQkzpgqSJbAPlOGvipmuvb/eSRFZnsgbkjgEjuqqZUAN\n" +
            "EtTsn6OWAJFcg8TRjUPeNZO0HPROqjSuzs7qQU6TUrJxBDPeHiClHCDqqrmtEMce\n" +
            "fDDsKkZ7YBKNlV76hHQ8/Noxv/p8UclCP/OSRCZn3EGi2xUB4VREoitPswOeB57j\n" +
            "l/EEo7Gcbezx/ryIRa/BeMncB2PWSmboiHpOlY9N7z5O6b7GngUdBqteBDZwJSuM\n" +
            "jRZvwd3lHxwwVFxIilGCgju/Z4V/aCG+NRbDHcj1djsMPvhh5vs/UTK7puPGMURM\n" +
            "HcR4pN7UocOdPufjRr3dZA8R+AOx0+A52DYMGTcJcUD/2gvBYZiKYTToW9DUNULD\n" +
            "Z8ipzWGcvuprxH2btozuCTkR8mwnZeNWaq62yy/E87DZDYFncNoZQma9/CDHOM4v\n" +
            "/eARlHVVfEpRBAHbB/ZQHfoXw4X+eNNG8x5V0ym19XL/EbWdbuuS507t9wB9RT+2\n" +
            "XFfE55qJfTUafYPvlmDX46CJBYEbFIDnhzDbu6rUNSFDKFwzPasrEkhLWlamY6Yh\n" +
            "fuf3GGQk9Wdq+qlz6VnENa2OmX8vOwIDAQABAoICABWdYfOPao9B/qs5GQhJVdMZ\n" +
            "hJbmGzYP/On6UNw+JHPR0UPRiUCfEulGHpIK3MNbj0PtOjAwDDcIi+ic9Tskej4/\n" +
            "pDm1UngaP/snI1HVIRp/ii4/5pbDZUKEYMJdcsdw/J1yQmAgUDmSMQuculupGXsh\n" +
            "dCVHr+Or424MdhKJAmw7BGnmQGdM/ba6tGSEOFnkwMJ+1latlcXA4bl4zyOyXpAZ\n" +
            "OftDznb9uQbqklApXe7alY3fJeazXNEpN0/Qs+12R1qk33robrygcTzheQ6xGdHa\n" +
            "qreUK/oSNjJLVcplwnLcguCOH+MpGVAM6B3e4AKhE0CA42sYGxQ3Brb8qbb8lo+K\n" +
            "SHjPXwHmZHYMx2pX1z/dVkzR4sgkxl3eANJYad1QF5y94G2eTzutue/4PPPzGN4F\n" +
            "xYpLaUuiInUpRyfxT7p9cdx8xDNL4dMcKkClGpbVdGv9h8QGnCUvZRV54kIl40hc\n" +
            "IjYFmtsO9CEDt/N5wFnADdkljBErICxjNpMhbMgiXChRBsCsaS3w5Iezx3+Ihvfy\n" +
            "B7QfC5aifmydFleShzQhGWkC9nNVtMBo5z+e+hGVsaCb5HRbgzHofFw/Tw7+i4hu\n" +
            "Fg38BvU/6V2VfkEBTF5HbIkU/ysmA8iHn2oBt4N8DoBdTaB1do3oP2qlA+PDLo2V\n" +
            "cYyoEKdJN4tu7iYbVD7pAoIBAQDjKz9csdo+4pFqrgdUorh8V5Xa5U/meiA4FSu6\n" +
            "w7PAPmJI5T2BmDqa3CwIWA59hO5jXFVVZq8JWkDXdo/LjnzZIIlMq7L4OJIphc52\n" +
            "TfjVE5vHRLJnW7Hd65zEFmJGAixxTi68xfESG/O2XPhkCqOHSLqvJdJmbA7+DVTu\n" +
            "IQt7EeJFS1JasXJnTOP9lJo7pe0/qG7E+4ekon4UdQDJjJspegXUFxFmAEMLbD2I\n" +
            "FbwypeDEodcfRdge/SYaM46e9PFTdgxUmog8VikRRZZRhvMDcE+0YfV76TxXYr3l\n" +
            "ImmFFCy4pePKiK79ZLqoNrMizCFmogsP8dubufF0mcTMkP1HAoIBAQDM8wqsq2hu\n" +
            "ZE+syWa4SQkYe7MC8doJxUOY+CXTLY6iJ8B86KQVKY+yfNdoxsJutg3cNiz2gCae\n" +
            "aLqhjesJVX84VGoXPB96Sg9bAxyjj6PvC7RUdz4PiMMsgY2tmRozWdfaXD3TM0HN\n" +
            "pnQI4Kl1A28ExotzUbfR3woFL53CPA5KgNauyHlt54v3c2hSfPx9X9/W41l+1C5x\n" +
            "ZHr9KdRkeF0nZc5OFBvD1DinDhFt9fj5HkdNEoIWnjv8aWNXGbexksucu0X3Dfm2\n" +
            "T8kerW1xT5dkv/ykOkVLQwm0IvlPqkjdPKDy7Py90Vbqw5dFLFvzJrrB+SL+jv4p\n" +
            "cYZ8yy8lbehtAoIBAQCUKmv8UIAxjeMcun9Lg4pih1nVWMWBZNxI1/4apXRDCi1e\n" +
            "sC4qrZhj0wDhPFXPJnm50spRllTJ+9TY85qcQMZLc/45RK/JWFR0wrJD1V1b1JtB\n" +
            "IBxgb50WSouIFbVpRheomz6+nzg6AIM3yXG1Bn9cSGKCxF9zsD0jFJz1aBYt4h87\n" +
            "5QHE54HfwHXfuiHSj8mrQHdnAUuaZOVpAFtQGeZF6jGNALK3Xapc8+86KDsEqc5t\n" +
            "UcWWvx5UL/a/FiuKn+Ya8p7eO6BqAiRtAH8nk6ZC8uj5lP7hH+HceSm0HnrGcr8s\n" +
            "e/6T5gyEd0OLXYn/Qzbx0vT2JGCBNIk47OZAKr0XAoIBABUteAjnnV7q1qDQHuEk\n" +
            "CuCQx6qiOxmPXLDN03rC1l5DJUzC7VGSfdq/s7KL90NhZIVAw9yk2Vi9Eavn8kWA\n" +
            "pCi58Ex+VfJY/MU2yRrNmO72kqe3up34T9KlgHJTw7VSr09NAMZ2IXKSpKLWNCx3\n" +
            "Ml2X9ojwBMKW/X4TsYWElyVzsrtU09dbeccUEc+UQrLh2UtnKrREUJg+/cZzMBNB\n" +
            "rL6Jcov23/eYUlJQzdRC+nsjedKo+vBDYYdvjGhPq/+ZX5jOcShaNVd1Xx7gZNK0\n" +
            "mrw6amy96LMiNjp68rActHLH9QmlG2ix3P1dQKBROR8i/WFV0RvkwradmHwEstZ3\n" +
            "SPECggEAB1JjhXjJ2FRzt6bp/m3MruRhsxStkb5yOVa4GikH98/u7H+GQAahFMyn\n" +
            "cl52deU9/wEofmfsBL/8MmTAB+rw3a8ZZKteP72eKhLe2P7kH920Kh228Et9Pow5\n" +
            "p29Nuxn/M+vcxNQlWEAGzEoZJx7HO+QplNRSD8BozBb23Vy5p8jJ0v8lJvRujrXN\n" +
            "4NQ/LjgOXKwmy7zcROQDvPzE1Q1EgaktGfjOmtdzJICYPYGCI3eI/UuXH8I82OR0\n" +
            "KdcIEKN4E2SViW7Wsz132MiKeBEaGmk++iG+jAmTVAKxZneluE6AANGgXUJpmjbo\n" +
            "9nOok7h3Rhh6U04s37f8yTE1uuBaAA==";

    private String pub = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtd4iA+xZfFqDT255UwA7\n" +
            "1P0Qi7UAXfkQdxWOKuQvQuSXgRgxPV+HUwXP9DcLrMqtdFT/Wzaa53k2CdKje6se\n" +
            "GNfzbGm0pnYgUkUJM6YKkiWwD5Thr4qZrr2/3kkRWZ7IG5I4BI7qqmVADRLU7J+j\n" +
            "lgCRXIPE0Y1D3jWTtBz0Tqo0rs7O6kFOk1KycQQz3h4gpRwg6qq5rRDHHnww7CpG\n" +
            "e2ASjZVe+oR0PPzaMb/6fFHJQj/zkkQmZ9xBotsVAeFURKIrT7MDngee45fxBKOx\n" +
            "nG3s8f68iEWvwXjJ3Adj1kpm6Ih6TpWPTe8+Tum+xp4FHQarXgQ2cCUrjI0Wb8Hd\n" +
            "5R8cMFRcSIpRgoI7v2eFf2ghvjUWwx3I9XY7DD74Yeb7P1Eyu6bjxjFETB3EeKTe\n" +
            "1KHDnT7n40a93WQPEfgDsdPgOdg2DBk3CXFA/9oLwWGYimE06FvQ1DVCw2fIqc1h\n" +
            "nL7qa8R9m7aM7gk5EfJsJ2XjVmqutssvxPOw2Q2BZ3DaGUJmvfwgxzjOL/3gEZR1\n" +
            "VXxKUQQB2wf2UB36F8OF/njTRvMeVdMptfVy/xG1nW7rkudO7fcAfUU/tlxXxOea\n" +
            "iX01Gn2D75Zg1+OgiQWBGxSA54cw27uq1DUhQyhcMz2rKxJIS1pWpmOmIX7n9xhk\n" +
            "JPVnavqpc+lZxDWtjpl/LzsCAwEAAQ==";

    public ClientAPI() throws InvalidKeySpecException, NoSuchAlgorithmException {

    }


    private RSAPublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        Base64 b64 = new Base64();
        byte [] decoded = b64.decode(pub);
        return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(decoded));
    }

    private RSAPrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        Base64 b64 = new Base64();
        byte [] decoded = b64.decode(priv);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }



    public String[] getDataFromAPI() throws InvalidKeySpecException, NoSuchAlgorithmException {

        String jwt = JWT.create().withClaim("name", "name").sign(getAlgorithm());

        MultiValueMap<String, String> headers =new HttpHeaders();
        headers.add("Authorization", "Bearer "+ jwt);
        HttpEntity httpEntity = new HttpEntity(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String[]> exchange = restTemplate.exchange("http://localhost:8080/api/book",
                HttpMethod.GET,
                httpEntity,
                String[].class);
        System.out.println(exchange.getBody()[0]);
        return exchange.getBody();
    }

    private Algorithm getAlgorithm() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return Algorithm.RSA512(getPublicKey(),getPrivateKey());
    }


}

