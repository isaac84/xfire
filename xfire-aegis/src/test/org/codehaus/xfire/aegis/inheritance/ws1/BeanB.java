package org.codehaus.xfire.aegis.inheritance.ws1;

/**
 * <br/>
 * 
 * @author xfournet
 */
public class BeanB
    extends BeanA
{
    private String m_propB;

    public String getPropB()
    {
        return m_propB;
    }

    public void setPropB(String propB)
    {
        m_propB = propB;
    }

    public String toString()
    {
        return super.toString() + " ; propB=" + m_propB;
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
        if (!super.equals(o))
        {
            return false;
        }

        final BeanB beanB = (BeanB) o;

        if ((m_propB != null) ? (!m_propB.equals(beanB.m_propB)) : (beanB.m_propB != null))
        {
            return false;
        }

        return true;
    }

    public int hashCode()
    {
        int result = super.hashCode();
        result = 29 * result + (m_propB != null ? m_propB.hashCode() : 0);
        return result;
    }
}
