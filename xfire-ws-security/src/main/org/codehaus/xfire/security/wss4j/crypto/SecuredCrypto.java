package org.codehaus.xfire.security.wss4j.crypto;

import java.io.IOException;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Merlin;
import org.codehaus.xfire.util.ClassLoaderUtils;

/**
 * @author <a href="mailto:tsztelak@gmail.com">Tomasz Sztelak</a>
 * 
 */
public class SecuredCrypto extends Merlin {

	private static final Log log = LogFactory.getLog(SecuredCrypto.class);

	private static final String ENCRYPTER_KEY = "xfire.encrypter.class";

	private AbstractDecrypter decrypter;

	public SecuredCrypto(Properties props) throws WSSecurityException,
			IOException {
		super(props, SecuredCrypto.class.getClassLoader(), null);
	}

	public SecuredCrypto(Properties props, ClassLoader cl)
			throws WSSecurityException, IOException {
	    super();
		
		if (props == null) {
			return;
		}
		
		try {
			decrypter = loadDecrypter(props);
		} catch (Throwable e) {
			log.error("Can't load decrypter.");
		} 
		
		properties = decryptProperties(props);
		
		loadProperties(properties, cl, null);
	}

	/**
	 * @param props
	 * @return
	 * @throws ClassNotFoundException
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 */
	protected AbstractDecrypter loadDecrypter(Map props)
			throws ClassNotFoundException, InstantiationException,
			IllegalAccessException {
		String clazzName = (String) props.get(ENCRYPTER_KEY);

		if (clazzName == null) {
			log.debug("Using dummy decrypter");
			return new AbstractDecrypter() {

				public String decryptString(String value) {

					return value;
				}

			};
		}
		log.debug("Loading decrypter : " + clazzName);

		Class clazz = ClassLoaderUtils.loadClass(clazzName, getClass());
		
		if (!AbstractDecrypter.class.isAssignableFrom(clazz)) {
			log.error(clazzName + " is not instance of AbstractEncrypter");
			throw new RuntimeException(clazzName
					+ " is not instance of AbstractEncrypter");
		}
		return (AbstractDecrypter) clazz.newInstance();

	}

	private static final String[] PASS_KEYS = {
			"org.apache.ws.security.crypto.merlin.keystore.password",
			"org.apache.ws.security.crypto.merlin.alias.password" };

	protected Properties decryptProperties(Properties props) {

		String keys[] = getPassKeys();
		for (int i = 0; i < keys.length; i++) {
			String passKey = keys[i];
			String pass = props.getProperty(passKey);
			log.debug("Decrypting key value : "+passKey);
			if (pass != null) {
				pass = decryptString(pass);
				props.put(passKey, pass);
			}
		}
		return props;
	}

	protected String decryptString(String value) {
		return decrypter.decryptString(value);
	}

	protected String[] getPassKeys() {
		return PASS_KEYS;
	}
}
