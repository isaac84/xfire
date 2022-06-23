package org.codehaus.xfire.aegis.type.java5;

import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Set;

import javax.xml.namespace.QName;

import org.codehaus.xfire.aegis.AbstractXFireAegisTest;
import org.codehaus.xfire.aegis.type.Configuration;
import org.codehaus.xfire.aegis.type.CustomTypeMapping;
import org.codehaus.xfire.aegis.type.Type;
import org.codehaus.xfire.aegis.type.collection.CollectionType;
import org.codehaus.xfire.aegis.type.java5.dto.CollectionDTO;
import org.codehaus.xfire.aegis.type.java5.dto.DTOService;
import org.codehaus.xfire.aegis.type.java5.dto.ObjectDTO;
import org.codehaus.xfire.service.Service;
import org.jdom2.Document;

public class CollectionTest
    extends AbstractXFireAegisTest
{
    private CustomTypeMapping tm;
    private Java5TypeCreator creator;

    public void setUp() throws Exception
    {
        super.setUp();
        
        tm = new CustomTypeMapping();
        creator = new Java5TypeCreator();
        creator.setConfiguration(new Configuration());
        tm.setTypeCreator(creator);
    }

    public void testType() throws Exception
    {
        Method m = CollectionService.class.getMethod("getStrings", new Class[0]);
        
        Type type = creator.createType(m, -1);
        tm.register(type);
        assertTrue( type instanceof CollectionType );
        
        CollectionType colType = (CollectionType) type;
        QName componentName = colType.getSchemaType();
     
        assertEquals("ArrayOfString", componentName.getLocalPart());
        assertEquals("ArrayOfString", componentName.getLocalPart());
        
        type = colType.getComponentType();
        assertNotNull(type);
        assertTrue(type.getTypeClass().isAssignableFrom(String.class));
    }
    

    public void testRecursiveCollections() throws Exception
    {
        Method m = CollectionService.class.getMethod("getStringCollections", new Class[0]);
        
        Type type = creator.createType(m, -1);
        tm.register(type);
        assertTrue( type instanceof CollectionType );
        
        CollectionType colType = (CollectionType) type;
        QName componentName = colType.getSchemaType();
     
        assertEquals("ArrayOfArrayOfString", componentName.getLocalPart());
        
        type = colType.getComponentType();
        assertNotNull(type);
        assertTrue( type instanceof CollectionType );
        
        CollectionType colType2 = (CollectionType) type;
        componentName = colType2.getSchemaType();
     
        assertEquals("ArrayOfString", componentName.getLocalPart());
        
        type = colType2.getComponentType();
        assertTrue(type.getTypeClass().isAssignableFrom(String.class));
    }
    
    public void testPDType() throws Exception
    {
        PropertyDescriptor pd = 
            Introspector.getBeanInfo(CollectionDTO.class, Object.class).getPropertyDescriptors()[0];
        Type type = creator.createType(pd);
        tm.register(type);
        assertTrue( type instanceof CollectionType );
        
        CollectionType colType = (CollectionType) type;
        
        type = colType.getComponentType();
        assertNotNull(type);
        assertTrue(type.getTypeClass().isAssignableFrom(String.class));
    }

    public void testCollectionDTO()
    {
        CustomTypeMapping tm = new CustomTypeMapping();
        Java5TypeCreator creator = new Java5TypeCreator();
        creator.setConfiguration(new Configuration());
        tm.setTypeCreator(creator);
        
        Type dto = creator.createType(CollectionDTO.class);
        Set deps = dto.getDependencies();
        
        Type type = (Type) deps.iterator().next();

        assertTrue( type instanceof CollectionType );
        
        CollectionType colType = (CollectionType) type;
        
        deps = dto.getDependencies();
        assertEquals(1, deps.size());
        
        Type comType = colType.getComponentType();
        assertEquals(String.class, comType.getTypeClass());
    }

    public void testObjectDTO()
    {
        CustomTypeMapping tm = new CustomTypeMapping();
        Java5TypeCreator creator = new Java5TypeCreator();
        creator.setConfiguration(new Configuration());
        tm.setTypeCreator(creator);
        
        Type dto = creator.createType(ObjectDTO.class);
        Set deps = dto.getDependencies();
                               
        assertFalse( deps.isEmpty() );

        Type type = (Type) deps.iterator().next();

        assertTrue( type instanceof CollectionType );
        
        CollectionType colType = (CollectionType) type;
        
        deps = dto.getDependencies();
        assertEquals(1, deps.size());
        
        Type comType = colType.getComponentType();
        assertEquals(Object.class, comType.getTypeClass());
    }
    
    public void testCollectionDTOService() throws Exception
    {
        Service service = getServiceFactory().create(DTOService.class);
        getServiceRegistry().register(service);
        
        printNode(invokeService(service.getSimpleName(), "/org/codehaus/xfire/aegis/type/java5/dto/GetDTO.xml"));
    }
    
    public void testCollectionServiceWSDL() throws Exception
    {
        Service service = getServiceFactory().create(CollectionService.class);
        getServiceRegistry().register(service);
        
        
        Document wsdl = getWSDLDocument(service.getSimpleName());
        printNode(wsdl);
        assertValid("//xsd:element[@name='out'][@type='tns:ArrayOfString']", wsdl);
    }
    
    public void testUnannotatedStrings() throws Exception {
        Service endpoint = getServiceFactory().create(CollectionService.class);
        getServiceRegistry().register(endpoint);
        Document doc = getWSDLDocument("CollectionService");
        //printNode(doc);
        assertValid("//xsd:element[@name='getUnannotatedStringsResponse']/xsd:complexType/xsd:sequence/xsd:element[@type='tns:ArrayOfString']", doc);
    }
    
    public class CollectionService
    {
        public Collection<String> getStrings() 
        {
            return null;
        }
        
        public void setLongs(Collection<Long> longs) 
        {
        }
        
        public Collection getUnannotatedStrings(){
            return null;
        }
        
        public Collection<Collection<String>> getStringCollections()
        {
            return null;
        }
    }
}
