package org.codehaus.xfire.aegis.type.basic;

import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.xml.namespace.QName;

import org.codehaus.xfire.XFireRuntimeException;
import org.codehaus.xfire.aegis.AbstractXFireAegisTest;
import org.codehaus.xfire.aegis.type.Configuration;
import org.codehaus.xfire.aegis.type.CustomTypeMapping;
import org.codehaus.xfire.aegis.type.DefaultTypeCreator;
import org.codehaus.xfire.aegis.type.DefaultTypeMappingRegistry;
import org.codehaus.xfire.aegis.type.Type;
import org.codehaus.xfire.aegis.type.XMLTypeCreator;
import org.codehaus.xfire.aegis.type.collection.CollectionType;
import org.codehaus.xfire.soap.SoapConstants;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;

public class DescriptorTest
    extends AbstractXFireAegisTest
{
    CustomTypeMapping tm;
    private DefaultTypeMappingRegistry reg;

    protected void setUp()
        throws Exception
    {
        super.setUp();

        reg = new DefaultTypeMappingRegistry(true);
        tm = (CustomTypeMapping) reg.getDefaultTypeMapping();
        
        XMLTypeCreator creator = new XMLTypeCreator();
        creator.setConfiguration(reg.getConfiguration());
        DefaultTypeCreator next = new DefaultTypeCreator();
        next.setConfiguration(reg.getConfiguration());
        creator.setNextCreator(next);
        tm.setTypeCreator(creator);
    }

    public void testMapping() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean");

        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        Iterator elItr = info.getElements();
        assertTrue(elItr.hasNext());
        QName el = (QName) elItr.next();
        assertEquals("Prop1", el.getLocalPart());

        Iterator attItr = info.getAttributes();
        assertTrue(attItr.hasNext());
        QName att = (QName) attItr.next();
        assertEquals("Prop2", att.getLocalPart());
    }

    public void testMapping2() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean2");

        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        Iterator elItr = info.getElements();
        assertTrue(elItr.hasNext());
        QName el = (QName) elItr.next();
        assertEquals("Prop1", el.getLocalPart());

        assertTrue(elItr.hasNext());
        QName el2 = (QName) elItr.next();
        assertEquals("Prop2", el2.getLocalPart());
    }
    
    public void testParentWithMapping2() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean2");

        Type type = tm.getTypeCreator().createType(ParentOfMyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        Iterator elItr = info.getElements();
        assertTrue(elItr.hasNext());
        QName el = (QName) elItr.next();
        assertEquals("Prop1", el.getLocalPart());

        assertTrue(elItr.hasNext());
        QName el2 = (QName) elItr.next();
        assertEquals("Prop2", el2.getLocalPart());
    }

    public void testListHolder() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean");

        Type type = tm.getTypeCreator().createType(ListHolderBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        Iterator elItr = info.getElements();
        assertTrue(elItr.hasNext());
        QName el = (QName) elItr.next();
        assertEquals("Beans", el.getLocalPart());

        Type beanList = info.getType(el);
        assertTrue( beanList instanceof CollectionType );
    }

    public void testListHolderNoName() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean2");

        Type type = tm.getTypeCreator().createType(ListHolderBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        Iterator elItr = info.getElements();
        assertTrue(elItr.hasNext());
        QName el = (QName) elItr.next();
        assertEquals("beans", el.getLocalPart());

        Type beanList = info.getType(el);
        assertTrue( beanList instanceof CollectionType );
    }

    public void testDefaultName() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean4");

        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        Iterator attItr = info.getAttributes();
        assertTrue(attItr.hasNext());
        QName el = (QName) attItr.next();
        assertEquals("prop2", el.getLocalPart());
    }

    public void testNillable() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean-nillable");

        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        assertFalse(info.isNillable(new QName(info.getDefaultNamespace(), "prop1")));
        assertTrue(info.isNillable(new QName(info.getDefaultNamespace(), "prop2")));
    }
    
    public void testMinOccurs() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean-minoccurs");

        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        assertEquals(info.getMinOccurs(new QName(info.getDefaultNamespace(), "prop1")), 1);
        assertEquals(info.getMinOccurs(new QName(info.getDefaultNamespace(), "prop2")), 0);
    }
    
    public void testExtensible() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean-extensible");
        reg.getConfiguration().setDefaultExtensibleAttributes(true);
        reg.getConfiguration().setDefaultExtensibleElements(true);
        
        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();
        assertTrue(info.isExtensibleElements());
        assertTrue(info.isExtensibleAttributes());
    }
    
    public void testExtensibleOff() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean-extensibleoff");
        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();
        assertFalse(info.isExtensibleElements());
        assertFalse(info.isExtensibleAttributes());
    }

    public void testCustomType() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:custom-type");

        BeanType type = (BeanType) tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = type.getTypeInfo();

        QName name = (QName) info.getElements().next();
        Type custom = info.getType(name);
        assertTrue(custom instanceof MyStringType);
    }

    public void testSimpleXMLMapping() throws Exception
    {
        XMLTypeCreator creator = new XMLTypeCreator();
        creator.setNextCreator(new DefaultTypeCreator());
        creator.setConfiguration(new Configuration());
        tm = new CustomTypeMapping(new DefaultTypeMappingRegistry().createDefaultMappings());
        creator.setTypeMapping(tm);
        Type type = creator.createType(MyService1.class.getDeclaredMethod("getCollection", new Class[0]), -1);
        assertTrue("type is not a collection", type instanceof CollectionType);
        assertEquals("unexpected collection type", Double.class, ((CollectionType)type).getComponentType().getTypeClass());
        try
        {
            creator.createType(MyService1.class.getDeclaredMethod("getUnmapped", new Class[]{java.util.List.class}), 0);
            fail("Unmapped collection did not throw an exception");
        }
        catch(XFireRuntimeException ex)
        {
        }
        
        // assertEquals(new QName(tm.getEncodingStyleURI(), "doubles"), type.getSchemaType());
    }

    public void testBestMatch() throws Exception
    {
        XMLTypeCreator creator = new XMLTypeCreator();
        creator.setNextCreator(new DefaultTypeCreator());
        creator.setConfiguration(new Configuration());
        tm = new CustomTypeMapping(new DefaultTypeMappingRegistry().createDefaultMappings());
        creator.setTypeMapping(tm);
        Method method = MyService1.class.getDeclaredMethod("getCollection", new Class[0]);
        Type type = creator.createType(method, -1);
        assertTrue("type is not a collection", type instanceof CollectionType);
        assertEquals("unexpected collection return type for method " + method, Double.class, ((CollectionType)type).getComponentType().getTypeClass());
        
        method = MyService1.class.getDeclaredMethod("getCollection", new Class[]{Integer.TYPE});
        type = creator.createType(method, -1);
        assertEquals("unexpected collection return type for method " + method, Float.class, ((CollectionType)type).getComponentType().getTypeClass());
        
        type = creator.createType(method, 0);
        // assertEquals(new QName("urn:foo:bar", "int"), type.getSchemaType());
        
        method = MyService1.class.getDeclaredMethod("getCollectionForValues", new Class[]{Integer.TYPE, Collection.class});
        type = creator.createType(method, -1);
        assertEquals("unexpected collection return type for method " + method, Calendar.class, ((CollectionType)type).getComponentType().getTypeClass());
        
        method = MyService1.class.getDeclaredMethod("getCollectionForValues", new Class[]{String.class, Collection.class});
        type = creator.createType(method, -1);
        assertEquals("unexpected collection return type for method " + method, BigDecimal.class, ((CollectionType)type).getComponentType().getTypeClass());
        type = creator.createType(method, 1);
        assertEquals("unexpected collection parameter type for method " + method, Date.class, ((CollectionType)type).getComponentType().getTypeClass());
        try
        {
            creator.createType(method, 2);
            fail("Expected exception when requesting type for non-existent parameter index");
        }
        catch(Exception ex)
        {}
    }
    
    public void testMapping5() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:bean5");

        Type type = tm.getTypeCreator().createType(MyBean.class);
        BeanTypeInfo info = ((BeanType) type).getTypeInfo();

        Iterator elItr = info.getElements();
        assertFalse(elItr.hasNext());

        Iterator attItr = info.getAttributes();
        assertFalse(attItr.hasNext());
    }
    
    public void testCustomName() throws Exception
    {
        tm.setEncodingStyleURI("urn:xfire:custom-ns");

        BeanType type = (BeanType) tm.getTypeCreator().createType(MyBean.class);
        
        assertEquals(new QName("urn:Bean", "Bean"), type.getSchemaType());
        
        BeanTypeInfo info = type.getTypeInfo();
        assertEquals("urn:Bean", info.getDefaultNamespace());
        
        Iterator elItr = info.getElements();
        assertTrue(elItr.hasNext());

        QName prop1 = (QName) elItr.next();
        assertEquals(new QName("urn:Bean", "prop1"), prop1);

        System.out.println(info.getType(prop1));
        assertTrue(info.getType(prop1) instanceof StringType);
        
        Element root = new Element("root", Namespace.getNamespace("xsd", SoapConstants.XSD));
        new Document(root);
        Element schema = new Element("schema", Namespace.getNamespace("xsd", SoapConstants.XSD));
        root.addContent(schema);
        type.writeSchema(schema);

        addNamespace("xsd", SoapConstants.XSD);
        assertValid("//xsd:element[@name='prop1'][@type='xsd:string']", root);
    }
}
