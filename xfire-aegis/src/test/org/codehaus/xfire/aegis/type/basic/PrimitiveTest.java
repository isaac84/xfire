package org.codehaus.xfire.aegis.type.basic;

import org.codehaus.xfire.aegis.AbstractXFireAegisTest;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.services.PrimitiveService;
import org.jdom.Document;


/**
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 * @since Feb 21, 2004
 */
public class PrimitiveTest
        extends AbstractXFireAegisTest
{
    public void setUp()
            throws Exception
    {
        super.setUp();

        Service endpoint = getServiceFactory().create(PrimitiveService.class,
                                                      "PrimitiveService",
                                                      "urn:PrimitiveService",
                                                      null);
        getServiceRegistry().register(endpoint);
    }

    public void testWrappedPrimitive()
            throws Exception
    {
        Document response =
                invokeService("PrimitiveService", "/org/codehaus/xfire/aegis/type/basic/echoInteger.xml");

        addNamespace("p", "urn:PrimitiveService");
        assertValid("//p:out[text()='1']", response);

        Document doc = getWSDLDocument("PrimitiveService");
    }

    public void testPrimitive()
            throws Exception
    {
        Document response =
                invokeService("PrimitiveService", "/org/codehaus/xfire/aegis/type/basic/echoInt.xml");

        addNamespace("p", "urn:PrimitiveService");
        assertValid("//p:out[text()='1']", response);

        Document doc = getWSDLDocument("PrimitiveService");
    }
}
