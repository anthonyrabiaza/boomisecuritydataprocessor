package com.boomi.proserv.security.authentication;

public class AuthCodeHandlerFactory {
    static public AuthCodeHandler getAuthCodeHander(String implementation) throws Exception {
        AuthCodeHandler authCodeHandler;
        switch(implementation) {
            case "NimbusJOSE":
                authCodeHandler =  new NimbusJOSEAuthenticationCodeHandler();
                break;
            case "JOSE4J":
                authCodeHandler =  new JOSE4JAuthenticationCodeHandler();
                break;
            default:
                throw new Exception("Implementation " + implementation + "does not exist");
        }

        return authCodeHandler;
    }
}
