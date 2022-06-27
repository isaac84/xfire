package org.codehaus.xfire.security.wss4j;

import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.codehaus.xfire.MessageContext;
import org.codehaus.xfire.XFireRuntimeException;
import org.codehaus.xfire.exchange.OutMessage;
import org.codehaus.xfire.fault.XFireFault;
import org.codehaus.xfire.handler.Phase;
import org.codehaus.xfire.service.binding.AbstractBinding;
import org.codehaus.xfire.util.dom.DOMOutHandler;
import org.w3c.dom.Document;

public class WSS4JOutHandler
    extends AbstractWSS4JHandler
{
    protected static final Log log = LogFactory.getLog(WSS4JOutHandler.class.getName());

    private static Log tlog = LogFactory.getLog("org.apache.wss4j.dom.TIME");

    public WSS4JOutHandler()
    {
        super();
        
        setPhase(Phase.USER);
        getAfter().add(DOMOutHandler.class.getName());
    }
    
    public WSS4JOutHandler(Map props)
    {
        this();
        setProperties(props);
        
    }
    
   
    public void invoke(MessageContext mc)
        throws Exception
    {
        boolean doDebug = log.isDebugEnabled();

        long t0 = 0, t1 = 0, t2 = 0, t3 = 0;
        if (tlog.isDebugEnabled())
        {
            t0 = System.currentTimeMillis();
        }
       
        if (doDebug)
        {
            log.debug("WSDoAllSender: enter invoke()");
        }

        RequestData reqData = new RequestData();
        reqData.setWssConfig(getConfig());

        reqData.setMsgContext(mc);
        /*
         * The overall try, just to have a finally at the end to perform some
         * housekeeping.
         */
        try
        {
            /*
             * Get the action first.
             */
            String action = getString(WSHandlerConstants.ACTION, mc);
            if (action == null)
            {
                throw new XFireRuntimeException("WSDoAllSender: No action defined");
            }
            
            List<Integer> actions = WSSecurityUtil.decodeAction(action);
            if (actions.contains(WSConstants.NO_SECURITY))
            {
                return;
            }

            /*
             * For every action we need a username, so get this now. The
             * username defined in the deployment descriptor takes precedence.
             */
            reqData.setUsername((String) getOption(WSHandlerConstants.USER));
            if (reqData.getUsername() == null || reqData.getUsername().equals(""))
            {
                String username = (String) getProperty(reqData.getMsgContext(), WSHandlerConstants.USER);
                if (username != null)
                {
                    reqData.setUsername(username);
                }
            }
            
            /*
             * Now we perform some set-up for UsernameToken and Signature
             * functions. No need to do it for encryption only. Check if
             * username is available and then get a passowrd.
             */
            if (actions.contains(WSConstants.SIGN) || 
                    actions.contains(WSConstants.UT) || 
                    actions.contains(WSConstants.UT_SIGN))
            {
                /*
                 * We need a username - if none throw an XFireFault. For
                 * encryption there is a specific parameter to get a username.
                 */
                if (reqData.getUsername() == null || reqData.getUsername().equals(""))
                {
                	log.error("WSDoAllSender: Empty username for specified action");
                    throw new XFireFault("WSDoAllSender: Empty username for specified action", XFireFault.RECEIVER);
                }
            }
            if (doDebug)
            {
                log.debug("Action: " + actions);
                log.debug("Actor: " + reqData.getActor());
            }
            /*
             * Now get the SOAP part from the request message and convert it
             * into a Document.
             * 
             * This forces Axis to serialize the SOAP request into FORM_STRING.
             * This string is converted into a document.
             * 
             * During the FORM_STRING serialization Axis performs multi-ref of
             * complex data types (if requested), generates and inserts
             * references for attachements and so on. The resulting Document
             * MUST be the complete and final SOAP request as Axis would send it
             * over the wire. Therefore this must shall be the last (or only)
             * handler in a chain.
             * 
             * Now we can perform our security operations on this request.
             */
            OutMessage message = (OutMessage) mc.getCurrentMessage();
            Document doc = (Document) message.getProperty(DOMOutHandler.DOM_MESSAGE);
            if( doc == null ){
            	log.error("There is no DOM message in current message. Add DOMOutHandler to your handlers chain");
            	throw new XFireFault("There is no DOM message in current message. Add DOMOutHandler to your handlers chain",XFireFault.RECEIVER);
            }
            /**
             * There is nothing to send...Usually happens when the provider
             * needs to send a HTTP 202 message (with no content)
             */
            if (message == null)
            {
                return;
            }

            if (tlog.isDebugEnabled())
            {
                t1 = System.currentTimeMillis();
            }

            List<HandlerAction> handlerActions = WSSecurityUtil.decodeHandlerAction(action, null);
            doSenderAction(doc, reqData, handlerActions, AbstractBinding.isClientModeOn(mc));

            if (tlog.isDebugEnabled())
            {
                t2 = System.currentTimeMillis();
            }

            if (tlog.isDebugEnabled())
            {
                t3 = System.currentTimeMillis();
                tlog.debug("Send request: total= " + (t3 - t0) + " request preparation= "
                        + (t1 - t0) + " request processing= " + (t2 - t1) + " request to Axis= "
                        + (t3 - t2) + "\n");
            }

            if (doDebug)
            {
                log.debug("WSDoAllSender: exit invoke()");
            }
        }
        catch (WSSecurityException e)
        {
            throw new XFireFault(e.getMessage(), e, XFireFault.RECEIVER);
        }
        finally
        {
            reqData = null;
        }
    }
}
