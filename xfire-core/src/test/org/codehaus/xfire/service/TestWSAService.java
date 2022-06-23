package org.codehaus.xfire.service;

import org.codehaus.xfire.fault.XFireFault;
import org.jdom2.Element;

public interface TestWSAService
{
    Element echo(Element msg) throws XFireFault;
}
