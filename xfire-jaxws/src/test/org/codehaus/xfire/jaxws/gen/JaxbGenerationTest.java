package org.codehaus.xfire.jaxws.gen;

import org.codehaus.xfire.gen.Wsdl11Generator;
import org.codehaus.xfire.jaxws.AbstractJAXWSTest;

import com.sun.codemodel.JCodeModel;
import com.sun.codemodel.JDefinedClass;

public class JaxbGenerationTest
    extends AbstractJAXWSTest
{
    public void testGlobalWeather() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFile("src/wsdl/globalweather-twoporttypes.wsdl").getAbsolutePath());
        generator.setOutputDirectory(getTestFile("target/test-services").getAbsolutePath());
        generator.setDestinationPackage("services.global");
        generator.setProfile(JAXWSProfile.class.getName());
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("services.global.GlobalWeatherService");
        assertNotNull(echo);
    }
    
    public void testEchoHeader() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFile("src/wsdl/headerout.wsdl").getAbsolutePath());
        generator.setOutputDirectory(getTestFile("target/test-services").getAbsolutePath());
        generator.setDestinationPackage("services.headerout");
        generator.setProfile(JAXWSProfile.class.getName());
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("services.headerout.EchoPortType");
        assertNotNull(echo);
    }

    public void testEcho() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFile("src/wsdl/echo.wsdl").getAbsolutePath());
        generator.setOutputDirectory(getTestFile("target/test-services").getAbsolutePath());
        generator.setDestinationPackage("services.echo");
        generator.setProfile(JAXWSProfile.class.getName());
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("services.echo.EchoPortType");
        assertNotNull(echo);
    }
}
