package org.codehaus.xfire.aegis.inheritance.ws2.common.pack1;

/**
 * <br/>
 * 
 * @author xfournet
 */
public class ContentBean1
{
    private String m_data1;

    public ContentBean1()
    {
    }

    public ContentBean1(String data1)
    {
        m_data1 = data1;
    }

    public String getData1()
    {
        return m_data1;
    }

    public void setData1(String data1)
    {
        m_data1 = data1;
    }

    public String toString()
    {
        return "[" + getClass().getName() + "] data1=" + m_data1;
    }

    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        final ContentBean1 that = (ContentBean1) o;

        if (m_data1 != null ? !m_data1.equals(that.m_data1) : that.m_data1 != null)
        {
            return false;
        }

        return true;
    }

    public int hashCode()
    {
        return (m_data1 != null ? m_data1.hashCode() : 0);
    }
}
