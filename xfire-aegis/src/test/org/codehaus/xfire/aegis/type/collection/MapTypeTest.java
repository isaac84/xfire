package org.codehaus.xfire.aegis.type.collection;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;

import org.codehaus.xfire.MessageContext;
import org.codehaus.xfire.aegis.AbstractXFireAegisTest;
import org.codehaus.xfire.aegis.jdom.JDOMWriter;
import org.codehaus.xfire.aegis.stax.ElementReader;
import org.codehaus.xfire.aegis.type.DefaultTypeMappingRegistry;
import org.codehaus.xfire.aegis.type.Type;
import org.codehaus.xfire.aegis.type.TypeCreator;
import org.codehaus.xfire.aegis.type.TypeMapping;
import org.codehaus.xfire.aegis.type.TypeMappingRegistry;
import org.codehaus.xfire.aegis.type.basic.BeanType;
import org.codehaus.xfire.aegis.type.basic.SimpleBean;
import org.codehaus.xfire.aegis.type.basic.StringType;
import org.codehaus.xfire.aegis.type.collection.bean.MapBean;
import org.codehaus.xfire.client.XFireProxyFactory;
import org.codehaus.xfire.service.Service;
import org.codehaus.xfire.service.invoker.ObjectInvoker;
import org.codehaus.xfire.soap.SoapConstants;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;

public class MapTypeTest
    extends AbstractXFireAegisTest
{
    TypeMapping mapping;
    
    public void setUp() throws Exception
    {
        super.setUp();
        
        addNamespace("t", "urn:test");
        addNamespace("xsd", SoapConstants.XSD);
        addNamespace("xsi", SoapConstants.XSI_NS);
        
        TypeMappingRegistry reg = new DefaultTypeMappingRegistry(true);
        mapping = reg.createTypeMapping(true);
        mapping.setEncodingStyleURI("urn:test");
    }

    public void testBean()
        throws Exception
    {
        Type stringType = mapping.getTypeCreator().createType(String.class);
        
        MapType type = new MapType(new QName("urn:test", "map"), stringType, stringType);
        type.setTypeClass(Map.class);
        type.setTypeMapping(mapping);
        
        assertNotNull(type.getSchemaType());
        assertEquals("entry", type.getEntryName().getLocalPart());
        assertEquals("urn:test", type.getEntryName().getNamespaceURI());
        assertEquals("key", type.getKeyName().getLocalPart());
        assertEquals("urn:test", type.getKeyName().getNamespaceURI());
        assertEquals("value", type.getValueName().getLocalPart());
        assertEquals("urn:test", type.getValueName().getNamespaceURI());

        assertTrue(type.isComplex());
        
        Set deps = type.getDependencies();
        assertEquals(1, deps.size());
        Type stype = (Type) deps.iterator().next();
        assertTrue(stype instanceof StringType);
        
        // Test reading
        ElementReader reader = new ElementReader(getResourceAsStream("/org/codehaus/xfire/aegis/type/collection/Map.xml"));
        //MessageReader creader = reader.getNextElementReader();
        
        Map m = (Map) type.readObject(reader, new MessageContext());
        assertEquals(2, m.size());
        assertEquals("value1", m.get("key1"));
        assertEquals("value2", m.get("key2"));
        
        reader.getXMLStreamReader().close();
        
        // Test writing
        Element element = new Element("map", "urn:test");
        Document doc = new Document(element);
        JDOMWriter writer = new JDOMWriter(element);
        type.writeObject(m, writer, new MessageContext());
        writer.close();

        assertValid("/t:map/t:entry[1]/t:key[text()='key1']", element);
        assertValid("/t:map/t:entry[1]/t:value[text()='value1']", element);

        assertValid("/t:map/t:entry[2]/t:key[text()='key2']", element);
        assertValid("/t:map/t:entry[2]/t:value[text()='value2']", element);

        Element types = new Element("types", Namespace.getNamespace("xsd", SoapConstants.XSD));
        Element schema = new Element("schema", Namespace.getNamespace("xsd", SoapConstants.XSD));
        types.addContent(schema);
        
        doc = new Document(types);
        
        type.writeSchema(schema);

        assertValid("//xsd:complexType[@name='map']", doc);
        assertValid("//xsd:complexType[@name='map']/xsd:sequence/xsd:element[@name='entry']", doc);
        assertValid("//xsd:complexType[@name='map']/xsd:sequence/xsd:element[@name='entry']" +
                    "/xsd:complexType/xsd:sequence/xsd:element[@name='key'][@type='xsd:string']", doc);
        assertValid("//xsd:complexType[@name='map']/xsd:sequence/xsd:element[@name='entry']" +
                    "/xsd:complexType/xsd:sequence/xsd:element[@name='value'][@type='xsd:string']", doc);
    }
    
    public void testTypeCreator()
    {
        TypeCreator creator = mapping.getTypeCreator();

        BeanType beanType = (BeanType) creator.createType(MapBean.class);
        
        QName mapName = (QName) beanType.getTypeInfo().getElements().next();
        
        Type type = beanType.getTypeInfo().getType(mapName);
        assertTrue(type instanceof MapType);

        assertEquals(new QName(mapping.getEncodingStyleURI(), "string2SimpleBeanMap"), type.getSchemaType());
        
        MapType mapType = (MapType) type;
        assertEquals(SimpleBean.class, mapType.getValueType().getTypeClass());
        assertEquals(String.class, mapType.getKeyType().getTypeClass());
    }

    public void testService() throws Exception
    {
        Service service = getServiceFactory().create(MapService.class, null, "urn:MapService", null);
        getServiceRegistry().register(service);

        service.setProperty(ObjectInvoker.SERVICE_IMPL_CLASS, MapServiceImpl.class);
        
        XFireProxyFactory factory = new XFireProxyFactory(getXFire());
        MapService client = (MapService) factory.create(service, "xfire.local://MapService");

        // this fails when we do it... Woodstox bug?
//        Client xclient = Client.getInstance(client);
//        xclient.addOutHandler(new DOMOutHandler());
//        xclient.addOutHandler(new LoggingHandler());
//        
        Map map = new HashMap();
        SimpleBean bean = new SimpleBean();
        bean.setHowdy("howdy");
        map.put("test", bean);
        map = client.echoMap(map);
        assertNotNull(map);
        assertEquals(1, map.size());
        bean = (SimpleBean) map.get("test");
        assertNotNull(bean);
        assertEquals("howdy", bean.getHowdy());
        
        MapBean mapBean = new MapBean();
        mapBean.setMap(map);
        MapBean mapBean2 = client.echoMapBean(mapBean);
        assertEquals(1, mapBean2.getMap().size());
        
        map = new HashMap();
        List keyList = new ArrayList();
        keyList.add("key");
        List valueList = new ArrayList();
        valueList.add("value");
        map.put(keyList, valueList);
        
        Map map2 = client.echoMapOfCollections(map);
        assertEquals(1, map2.size());
    }
}