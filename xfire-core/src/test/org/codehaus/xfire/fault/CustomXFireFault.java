package org.codehaus.xfire.fault;

import org.jdom2.Element;

public class CustomXFireFault
    extends XFireFault
{
    public CustomXFireFault()
    {
        super("CustomFault", XFireFault.MUST_UNDERSTAND);
        
        getDetail().addContent(new Element("test"));
    }
}