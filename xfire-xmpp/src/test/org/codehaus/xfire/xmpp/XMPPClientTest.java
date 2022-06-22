package org.codehaus.xfire.xmpp;

import java.lang.reflect.Method;

import org.codehaus.xfire.addressing.AddressingInHandler;
import org.codehaus.xfire.addressing.AddressingOperationInfo;
import org.codehaus.xfire.addressing.AddressingOutHandler;
import org.codehaus.xfire.aegis.AbstractXFireAegisTest;
import org.codehaus.xfire.client.Client;
import org.codehaus.xfire.service.OperationInfo;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.service.binding.ObjectServiceFactory;
import org.codehaus.xfire.service.invoker.ObjectInvoker;
import org.codehaus.xfire.test.Echo;
import org.codehaus.xfire.test.EchoImpl;
import org.codehaus.xfire.transport.Channel;
import org.codehaus.xfire.transport.DefaultTransportManager;
import org.codehaus.xfire.transport.Transport;


/**
 * XFireTest
 *
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 */
public class XMPPClientTest
        extends AbstractXFireAegisTest
{
    private Transport clientTrans;
    private Transport serverTrans;

    String username = "xfireTestServer";
    String password = "password1";
    String server = "bloodyxml.com";
    String id = username + "@" + server;
    private Service service;
    private ObjectServiceFactory factory;
    
    public void setUp()
            throws Exception
    {
        super.setUp();

        clientTrans = new XMPPTransport(getXFire(), server, "xfireTestClient", "password2");
        serverTrans = new XMPPTransport(getXFire(), server, username, password);
        
        getXFire().getTransportManager().register(serverTrans);

        factory = new ObjectServiceFactory(getTransportManager()) {

            protected OperationInfo addOperation(Service endpoint, Method method, String style)
            {
                OperationInfo op = super.addOperation(endpoint, method, style);
                
                new AddressingOperationInfo(op);
                
                return op;
            }
            
        };
        factory.addSoap11Transport(XMPPTransport.BINDING_ID);
        
        service = factory.create(Echo.class);
        service.setProperty(ObjectInvoker.SERVICE_IMPL_CLASS, EchoImpl.class);

        getServiceRegistry().register(service);
   //     XMPPConnection.DEBUG_ENABLED = true;       
    }
    
    protected void tearDown()
        throws Exception
    {
        clientTrans.dispose();
        serverTrans.dispose();
        
        super.tearDown();
    }

    public void testInvoke()
            throws Exception
    {
        Channel serverChannel = serverTrans.createChannel("Echo");

        DefaultTransportManager tm = new DefaultTransportManager();
        tm.initialize();
        tm.register(clientTrans);
       
        ObjectServiceFactory sf = new ObjectServiceFactory(tm);
        sf.addSoap11Transport(XMPPTransport.BINDING_ID);
        Service serviceModel = sf.create(Echo.class);
        Client client = new Client(clientTrans, serviceModel, id + "/Echo");
        client.setTimeout(10000);
     
        OperationInfo op = serviceModel.getServiceInfo().getOperation("echo");
        Object[] response = client.invoke(op, new Object[] {"hello"});

        assertNotNull(response);
        assertEquals(1, response.length);
        
        String resString = (String) response[0];
        assertEquals("hello", resString);
    }
    
    public void testInvokeWithAddressing()
        throws Exception
    {
        service.addInHandler(new AddressingInHandler());
        service.addOutHandler(new AddressingOutHandler());
        service.addFaultHandler(new AddressingOutHandler());

        Channel serverChannel = serverTrans.createChannel("Echo");

        DefaultTransportManager tm = new DefaultTransportManager();
        tm.initialize();
        tm.register(clientTrans);

        factory = new ObjectServiceFactory(tm) {

            protected OperationInfo addOperation(Service endpoint, Method method, String style)
            {
                OperationInfo op = super.addOperation(endpoint, method, style);
                
                new AddressingOperationInfo(op);
                
                return op;
            }
        };
        factory.addSoap11Transport(XMPPTransport.BINDING_ID);
        
        Service serviceModel = factory.create(Echo.class);
        
        Client client = new Client(clientTrans, serviceModel, id + "/Echo");
        client.addInHandler(new AddressingInHandler());
        client.addOutHandler(new AddressingOutHandler());
        client.addFaultHandler(new AddressingInHandler());
        
        OperationInfo op = serviceModel.getServiceInfo().getOperation("echo");
        Object[] response = client.invoke(op, new Object[] { "hello" });

        assertNotNull(response);
        assertEquals(1, response.length);

        String resString = (String) response[0];
        assertEquals("hello", resString);
    }
}
