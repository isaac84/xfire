package org.codehaus.xfire.generator;

import org.codehaus.xfire.gen.Wsdl11Generator;

import com.sun.codemodel.JCodeModel;
import com.sun.codemodel.JDefinedClass;
import com.sun.codemodel.JMethod;

public class JaxbGenerationTest
    extends GenerationTestSupport
{    
    public void testEchoWithFaults() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/echoFault.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setOverwrite(true);        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("xfire.echo.fault.OtherEchoException");
        assertNotNull(echo);
        echo = model._getClass("xfire.echo.fault.EchoException");
        assertNotNull(echo);
    }
    
    public void testWWCars() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/wwcarsXMLInterface.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setDestinationPackage("jsr181.jaxb.wwcars");
        generator.setBinding("jaxb");
        generator.setOverwrite(true);
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("jsr181.jaxb.wwcars.wwcarsXMLInterfaceSoap");
        assertNotNull(echo);
        
        assertEquals(getTestFile("src/wsdl/wwcarsXMLInterface.wsdl").toURI().toString(), generator.getBaseURI());
    }
    
    public void testTwoPortsDifferentBindings() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/globalweather-twoporttypes.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setDestinationPackage("jsr181.jaxb.globalweather.twopts");
        generator.setBinding("jaxb");
        generator.setOverwrite(true);
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("jsr181.jaxb.globalweather.twopts.GlobalWeatherSoap");
        assertNotNull(echo);
    }
    
    public void testFault() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/auth.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setDestinationPackage("jsr181.jaxb.auth");
        generator.setBinding("jaxb");
        generator.setOverwrite(true);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("jsr181.jaxb.auth.AuthServicePortType");
        assertNotNull(echo);
    }
    
    public void testGlobalWeather() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/globalweather.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setDestinationPackage("jsr181.jaxb.globalweather");
        generator.setBinding("jaxb");
        generator.setOverwrite(true);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("jsr181.jaxb.globalweather.GlobalWeatherSoap");
        assertNotNull(echo);
    }

    public void testEchoWrappedServiceIntf() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/echoWrapped.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setDestinationPackage("jsr181.jaxb.echo.wrapped");
        generator.setOverwrite(true);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("jsr181.jaxb.echo.wrapped.EchoPortType");
        assertNotNull(echo);
        
        /*JMethod method = echo.getMethod("echo", new JType[] { model._ref(String.class) });
        assertNotNull(method);
        assertEquals( model.ref(String.class), method.type() );
        
        assertNotNull(model._getClass("jsr181.jaxb.echo.wrapped.EchoClient"));
        assertNotNull(model._getClass("jsr181.jaxb.echo.wrapped.EchoImpl"));*/
    }
    

    public void testEchoNoDestPkg() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/echoWrapped.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setOverwrite(true);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("echo.wrapped.EchoPortType");
        assertNotNull(echo);
    }
    
    public void testEchoNoServerStubs() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/echoWrapped.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setDestinationPackage("org.codehaus.xfire.generator.noserverstubs");
        generator.setOverwrite(true);
        generator.setGenerateServerStubs(false);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("org.codehaus.xfire.generator.noserverstubs.EchoImpl");
        assertNull(echo);
    }
    
    public void testEchoUnbounded() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/echo-wrapped-unbounded.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setOverwrite(true);
        generator.setGenerateServerStubs(false);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("echo.wrapped.unbounded.EchoPortType");
        assertNotNull(echo);
        
        JMethod jm = echo.methods().iterator().next();
        assertEquals("java.util.List<java.lang.String>", jm.type().fullName());
    }
    
    public void testEchoUnboundedWithKeyword() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/echo-wrapped-keyword.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setOverwrite(true);
        generator.setGenerateServerStubs(false);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("echo.wrapped.keyword.EchoPortType");
        assertNotNull(echo);
        
        JMethod jm = echo.methods().iterator().next();
        assertEquals("java.util.List<java.lang.String>", jm.type().fullName());
    }
    
    public void testWrappedMTOMEcho() throws Exception
    {
        Wsdl11Generator generator = new Wsdl11Generator();
        generator.setWsdl(getTestFilePath("src/wsdl/echo-wrapped-mtom.wsdl"));
        generator.setOutputDirectory(getTestFilePath("target/test-services"));
        generator.setOverwrite(true);
        generator.setGenerateServerStubs(false);
        
        generator.generate();
        
        JCodeModel model = generator.getCodeModel();
        JDefinedClass echo = model._getClass("echo.wrapped.mtom.EchoPortType");
        assertNotNull(echo);
        
        JMethod jm = echo.methods().iterator().next();
        assertEquals("javax.activation.DataHandler", jm.type().fullName());
    }
}
