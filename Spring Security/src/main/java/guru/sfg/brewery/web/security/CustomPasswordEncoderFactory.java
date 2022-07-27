package guru.sfg.brewery.web.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;

import java.util.HashMap;
import java.util.Map;

public class CustomPasswordEncoderFactory {

    //Form PasswordEncoderFactories.createDelegatingPasswordEncoder() copy method and use whatever we want.
    public static PasswordEncoder createDelegatingPasswordEncoder() {
        //for custom BCrypt Encoder :
            String customBCryptId = "bcrypt15";
            Map<String, PasswordEncoder> encoders = new HashMap();
            //custom BCrypt line 18.
            encoders.put(customBCryptId, new BCryptPasswordEncoder(10));
            encoders.put("bcrypt", new BCryptPasswordEncoder());
            encoders.put("ldap", new LdapShaPasswordEncoder());
            encoders.put("noop", NoOpPasswordEncoder.getInstance());
            encoders.put("sha256", new StandardPasswordEncoder());
            return new DelegatingPasswordEncoder(customBCryptId, encoders);
    }
    private CustomPasswordEncoderFactory() {
    }
}
