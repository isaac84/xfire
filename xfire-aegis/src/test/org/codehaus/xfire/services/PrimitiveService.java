package org.codehaus.xfire.services;

/**
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 */
public class PrimitiveService
{
    public Integer echoInteger( Integer integer )
    {
        return integer;
    }

    public int echoInt( int integer )
    {
        return integer;
    }
}
