package pl.plenczewski.jwttokenclinet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.plenczewski.jwttokenclinet.services.ClientAPI;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
public class controller {

    @Autowired
    ClientAPI clientAPI;
    @GetMapping("/test")
    public void getData() throws InvalidKeySpecException, NoSuchAlgorithmException {
        clientAPI.getDataFromAPI();
    }



}
