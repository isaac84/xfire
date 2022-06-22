package org.codehaus.xfire.jaxb2;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.codehaus.xfire.aegis.type.Type;
import org.codehaus.xfire.service.MessagePartInfo;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.service.binding.ObjectServiceFactory;
import org.codehaus.xfire.soap.SoapConstants;
import org.codehaus.xfire.test.AbstractXFireTest;
import org.codehaus.xfire.util.dom.DOMInHandler;
import org.codehaus.xfire.util.dom.DOMOutHandler;
import org.jdom.Document;

/**
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 */
public class WeatherServiceTest
        extends AbstractXFireTest
{
    private Service service;
    private ObjectServiceFactory factory;

    public void setUp()
            throws Exception
    {
        super.setUp();

        factory = new JaxbServiceFactory(getXFire().getTransportManager());
        factory.setStyle(SoapConstants.STYLE_DOCUMENT);
        
        // Set the schemas
        ArrayList<String> schemas = new ArrayList<String>();
        schemas.add(getTestFile("src/test-schemas/WeatherForecast.xsd").getAbsolutePath());
        Map<String,Object> props = new HashMap<String,Object>();
        props.put(ObjectServiceFactory.SCHEMAS, schemas);
        
        service = factory.create(WeatherService.class,
                                  "WeatherService",
                                  "urn:WeatherService",
                                  props);
        
        getServiceRegistry().register(service);
    }

    public void testService()
            throws Exception
    {
        MessagePartInfo info = (MessagePartInfo)
            service.getServiceInfo().getOperation("GetWeatherByZipCode").getInputMessage().getMessageParts().get(0);

        assertNotNull(info);
        
        Type type = (Type) info.getSchemaType();
        assertTrue(type instanceof JaxbType);
        
        assertTrue(type.isComplex());
        assertFalse(type.isWriteOuter());
        
        assertEquals(new QName("http://www.webservicex.net", "GetWeatherByZipCode"), info.getName());
        
        Document response = invokeService("WeatherService", "GetWeatherByZip.xml");

        addNamespace("w", "http://www.webservicex.net");
        assertValid("//s:Body/w:GetWeatherByZipCodeResponse/w:GetWeatherByZipCodeResult", response);
    }

    /**
     * We want to test with DOM mode to make sure that we aren't writing to the output stream.
     * @throws Exception
     */
    public void testServiceWithDOMMode()
            throws Exception
    {
        service.addInHandler(new DOMInHandler());
        service.addOutHandler(new DOMOutHandler());
        
        MessagePartInfo info = (MessagePartInfo)
            service.getServiceInfo().getOperation("GetWeatherByZipCode").getInputMessage().getMessageParts().get(0);

        assertNotNull(info);
        
        Type type = (Type) info.getSchemaType();
        assertTrue(type instanceof JaxbType);
        
        assertTrue(type.isComplex());
        assertFalse(type.isWriteOuter());
        
        assertEquals(new QName("http://www.webservicex.net", "GetWeatherByZipCode"), info.getName());
        
        Document response = invokeService("WeatherService", "GetWeatherByZip.xml");

        addNamespace("w", "http://www.webservicex.net");
        assertValid("//s:Body/w:GetWeatherByZipCodeResponse/w:GetWeatherByZipCodeResult", response);
    }
    
    public void testWsdl() throws Exception
    {
        Document doc = getWSDLDocument("WeatherService");
printNode(doc);
        addNamespace("xsd", SoapConstants.XSD);
        
        assertValid("//xsd:schema[@targetNamespace='http://www.webservicex.net'][1]", doc);
        assertInvalid("//xsd:schema[@targetNamespace='http://www.webservicex.net'][2]", doc);
    }
}
