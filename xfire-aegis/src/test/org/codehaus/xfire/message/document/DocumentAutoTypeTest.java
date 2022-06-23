package org.codehaus.xfire.message.document;

import org.codehaus.xfire.aegis.AbstractXFireAegisTest;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.service.binding.ObjectServiceFactory;
import org.codehaus.xfire.services.BeanService;
import org.codehaus.xfire.soap.SoapConstants;
import org.codehaus.xfire.wsdl.AbstractWSDL;
import org.codehaus.xfire.wsdl.WSDLWriter;
import org.jdom2.Document;

/**
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 * @since Feb 21, 2004
 */
public class DocumentAutoTypeTest
        extends AbstractXFireAegisTest
{
    public void setUp()
            throws Exception
    {
        super.setUp();

        ((ObjectServiceFactory) getServiceFactory()).setStyle(SoapConstants.STYLE_DOCUMENT);
        Service service = getServiceFactory().create(BeanService.class, "Bean", "urn:Bean", null);
        service.setProperty(AbstractWSDL.GENERATE_IMPORTS, "true");
        getServiceRegistry().register(service);
    }

    public void testBeanService()
            throws Exception
    {
        Document response =
                invokeService("Bean", "/org/codehaus/xfire/message/document/bean11.xml");

        addNamespace("sb", "urn:Bean");
        addNamespace("svc", "http://services.xfire.codehaus.org");
        assertValid("//sb:getSimpleBeanout", response);
        assertValid("//sb:getSimpleBeanout/svc:howdy[text()=\"howdy\"]", response);
        assertValid("//sb:getSimpleBeanout/svc:bleh[text()=\"bleh\"]", response);
    }

    public void testBeanServiceWSDL()
            throws Exception 
    {
        // Test WSDL generation
        Document doc = getWSDLDocument("Bean");

        addNamespace("wsdl", WSDLWriter.WSDL11_NS);
        addNamespace("wsdlsoap", WSDLWriter.WSDL11_SOAP_NS);
        addNamespace("xsd", SoapConstants.XSD);

        assertValid("/wsdl:definitions/wsdl:types", doc);
        assertValid("/wsdl:definitions/wsdl:types/xsd:schema", doc);
        assertValid("/wsdl:definitions/wsdl:types" +
                    "/xsd:schema[@targetNamespace='http://services.xfire.codehaus.org']" +
                    "/xsd:complexType", doc);
        assertValid("/wsdl:definitions/wsdl:types" +
                    "/xsd:schema[@targetNamespace='http://services.xfire.codehaus.org']" +
                    "/xsd:complexType", doc);
        assertValid("/wsdl:definitions/wsdl:types" +
                    "/xsd:schema[@targetNamespace='http://services.xfire.codehaus.org']" +
                    "/xsd:complexType[@name=\"SimpleBean\"]", doc);
        assertValid("/wsdl:definitions/wsdl:types" +
                    "/xsd:schema[@targetNamespace='http://services.xfire.codehaus.org']" +
                    "/xsd:complexType[@name=\"SimpleBean\"]/xsd:sequence/xsd:element[@name=\"bleh\"]", doc);
        assertValid("/wsdl:definitions/wsdl:types" +
                    "/xsd:schema[@targetNamespace='http://services.xfire.codehaus.org']" +
                    "/xsd:complexType[@name=\"SimpleBean\"]/xsd:sequence/xsd:element[@name=\"howdy\"]", doc);
        assertValid("/wsdl:definitions/wsdl:types" +
                    "/xsd:schema[@targetNamespace='http://services.xfire.codehaus.org']" +
                    "/xsd:complexType[@name=\"SimpleBean\"]/xsd:sequence/xsd:element[@type=\"xsd:string\"]", doc);

        assertValid(
                "/wsdl:definitions/wsdl:service/wsdl:port/wsdlsoap:address[@location=\"http://localhost/services/Bean\"]",
                doc);
        
        String services = "http://services.xfire.codehaus.org";
        String sb = "urn:Bean";
        
        assertValid("//xsd:schema[@targetNamespace='" + sb
                    + "']/xsd:import[@namespace='" + services + "']", doc);
    }
}
