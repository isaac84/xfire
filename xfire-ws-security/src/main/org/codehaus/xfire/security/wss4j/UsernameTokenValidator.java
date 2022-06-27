package org.codehaus.xfire.security.wss4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.xml.security.utils.XMLUtils;

public class UsernameTokenValidator extends org.apache.wss4j.dom.validate.UsernameTokenValidator {
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(UsernameTokenValidator.class);
    
    @Override
    protected void verifyPlaintextPassword(UsernameToken usernameToken,
            RequestData data) throws WSSecurityException {
        
        if (data.getCallbackHandler() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
        }

        String user = usernameToken.getName();
        String password = usernameToken.getPassword();
        String nonce = usernameToken.getNonce();
        String createdTime = usernameToken.getCreated();
        String pwType = usernameToken.getPasswordType();
        boolean passwordsAreEncoded = usernameToken.getPasswordsAreEncoded();

        WSPasswordCallback pwCb =
            new WSPasswordCallback(user, password, pwType, WSPasswordCallback.USERNAME_TOKEN);
        try {
            data.getCallbackHandler().handle(new Callback[]{pwCb});
        } catch (IOException | UnsupportedCallbackException e) {
            LOG.debug(e.getMessage(), e);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e
            );
        }
        String origPassword = pwCb.getPassword();
        if (origPassword == null) {
            LOG.warn("Callback supplied no password for: {}", user);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
        if (usernameToken.isHashed()) {
            byte[] decodedNonce = XMLUtils.decode(nonce);
            byte[] decodedPassword = XMLUtils.decode(password);
            byte[] passDigest;
            if (passwordsAreEncoded) {
                passDigest = UsernameTokenUtil.doRawPasswordDigest(decodedNonce, createdTime,
                                                            XMLUtils.decode(origPassword));
            } else {
                passDigest = UsernameTokenUtil.doRawPasswordDigest(decodedNonce, createdTime,
                        origPassword.getBytes(StandardCharsets.UTF_8));
            }
            if (!MessageDigest.isEqual(decodedPassword, passDigest)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
        } else {
            byte[] origPasswordBytes = origPassword.getBytes(StandardCharsets.UTF_8);
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
            if (!MessageDigest.isEqual(origPasswordBytes, passwordBytes)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
        }
        
    }
}
