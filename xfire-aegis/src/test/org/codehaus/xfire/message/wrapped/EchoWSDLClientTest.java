package org.codehaus.xfire.message.wrapped;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.wsdl.Definition;
import javax.wsdl.factory.WSDLFactory;
import javax.xml.namespace.QName;

import org.codehaus.xfire.XFire;
import org.codehaus.xfire.XFireFactory;
import org.codehaus.xfire.aegis.AbstractXFireAegisTest;
import org.codehaus.xfire.aegis.AegisBindingProvider;
import org.codehaus.xfire.client.Client;
import org.codehaus.xfire.server.http.XFireHttpServer;
import org.codehaus.xfire.service.OperationInfo;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.service.binding.ObjectServiceFactory;
import org.codehaus.xfire.service.invoker.ObjectInvoker;
import org.codehaus.xfire.soap.AbstractSoapBinding;
import org.codehaus.xfire.test.Echo;
import org.codehaus.xfire.test.EchoImpl;
import org.codehaus.xfire.transport.local.LocalTransport;
import org.codehaus.xfire.wsdl11.parser.WSDLServiceBuilder;
import org.xml.sax.InputSource;

/**
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 */
public class EchoWSDLClientTest
        extends AbstractXFireAegisTest
{
    private Service service;

    public void setUp() throws Exception
    {
        super.setUp();

        service = getServiceFactory().create(Echo.class, "Echo", "urn:Echo", null);
        service.setProperty(ObjectInvoker.SERVICE_IMPL_CLASS, EchoImpl.class);

        getServiceRegistry().register(service);
    }

    protected void tearDown()
        throws Exception
    {
        getServiceRegistry().unregister(service);
        
        super.tearDown();
    }

    protected XFire getXFire()
    {
        return XFireFactory.newInstance().getXFire();
    }

    public void testInvoke()
            throws Exception
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        getWSDL("Echo").write(bos);

        WSDLServiceBuilder builder = new WSDLServiceBuilder(new ByteArrayInputStream(bos.toByteArray()));
        builder.setTransportManager(getTransportManager());
        builder.build();
        
        Service service = (Service) builder.getAllServices().iterator().next();
        assertTrue(service.getBindingProvider() instanceof AegisBindingProvider);
        AbstractSoapBinding binding = (AbstractSoapBinding) service.getBindings().iterator().next();
        
        Client client = new Client(binding, "xfire.local://" + service.getSimpleName());
        client.setXFire(getXFire());
        client.setTransport(getTransportManager().getTransport(LocalTransport.BINDING_ID));
        
        OperationInfo op = service.getServiceInfo().getOperation("echo");

        Object[] response = client.invoke(op, new Object[] {"hello"});

        assertNotNull(response);
        assertEquals(1, response.length);
        
        assertEquals("hello", response[0]);
    }
    
    public void testHTTPInvoke() throws Exception
    {
        XFireHttpServer server = new XFireHttpServer();
        server.setPort(8191);
        server.start();
        
        Client client = new Client(new URL("http://localhost:8191/Echo?wsdl"));
        
        OperationInfo op = client.getService().getServiceInfo().getOperation("echo");

        Object[] response = client.invoke(op, new Object[] {"hello"});

        assertNotNull(response);
        assertEquals(1, response.length);
        
        server.stop();
    }
    
    public void testWSDLWithSpecifiedInterface() throws Exception
    {
    	Map props = new HashMap();
        props.put(ObjectServiceFactory.PORT_TYPE, new QName("urn:EchoInterface", "Echo"));
        Service service = getServiceFactory().create(Echo.class, "EchoTest", "urn:EchoTest", props);
        service.setProperty(ObjectInvoker.SERVICE_IMPL_CLASS, EchoImpl.class);
        getServiceRegistry().register(service);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        getXFire().generateWSDL(service.getSimpleName(), baos);
        System.out.println(baos.toString());
        InputSource is = new InputSource(new ByteArrayInputStream(baos.toByteArray()));
    	Definition def = WSDLFactory.newInstance().newWSDLReader().readWSDL(null, is);
    	javax.wsdl.Service wsdlSvc = def.getService(new QName("urn:EchoTest", "EchoTest"));
    	assertNotNull(def.getPortType(new QName("urn:EchoInterface", "Echo")));
    }
}