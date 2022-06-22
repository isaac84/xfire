package org.codehaus.xfire.xmpp;

import org.codehaus.xfire.soap.Soap11;
import org.codehaus.xfire.soap.SoapVersion;
import org.codehaus.xfire.test.AbstractXFireTest;
import org.jivesoftware.smack.provider.ProviderManager;

/**
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 */
public class SoapIQProviderTest
    extends AbstractXFireTest
{
    public void testIQ()
        throws Exception
    {
        new SoapIQProvider();
     
        SoapVersion v11 = Soap11.getInstance();
        Object provider = ProviderManager.getIQProvider(v11.getEnvelope().getLocalPart(), 
                                                        v11.getEnvelope().getNamespaceURI());
        assertNotNull("Got null provider for " + v11.getEnvelope().getLocalPart() 
                + " in namespace " + v11.getEnvelope().getNamespaceURI(), provider);
        assertTrue(provider instanceof SoapIQProvider);
    }
}
