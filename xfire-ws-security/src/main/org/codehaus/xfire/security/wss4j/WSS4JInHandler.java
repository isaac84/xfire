package org.codehaus.xfire.security.wss4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import javax.security.auth.callback.CallbackHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.codehaus.xfire.MessageContext;
import org.codehaus.xfire.XFireRuntimeException;
import org.codehaus.xfire.exchange.AbstractMessage;
import org.codehaus.xfire.fault.XFireFault;
import org.codehaus.xfire.handler.Handler;
import org.codehaus.xfire.handler.Phase;
import org.codehaus.xfire.soap.handler.ReadHeadersHandler;
import org.codehaus.xfire.util.dom.DOMInHandler;
import org.w3c.dom.Document;

/**
 * Performs WS-Security inbound actions.
 *  
 * @author <a href="mailto:tsztelak@gmail.com">Tomasz Sztelak</a>
 */
public class WSS4JInHandler
    extends AbstractWSS4JHandler
    implements Handler
{
    protected static final Log log = LogFactory.getLog(WSS4JInHandler.class.getName());

    private static Log tlog = LogFactory.getLog("org.apache.wss4j.dom.TIME");

    private WSSecurityEngine secEngine;
    
    public WSS4JInHandler()
    {
        super();
        
        setPhase(Phase.PARSE);
        getBefore().add(ReadHeadersHandler.class.getName());
        getAfter().add(DOMInHandler.class.getName());
        
        secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(getConfig());
    }
    
    
    public WSS4JInHandler(Properties properties){
        this();
        setProperties(properties);
        
    }

    public void invoke(MessageContext msgContext)
        throws XFireFault
    {

        boolean doDebug = log.isDebugEnabled();

        if (doDebug)
        {
            log.debug("WSS4JInSecurityHandler: enter invoke()");
        }

        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
        if (tlog.isDebugEnabled())
        {
            t0 = System.currentTimeMillis();
        }

        RequestData reqData = new RequestData();
        reqData.setWssConfig(getConfig());
        /*
         * The overall try, just to have a finally at the end to perform some
         * housekeeping.
         */
        try
        {
            reqData.setMsgContext(msgContext);

            List<Integer> actions = new ArrayList<Integer>();
            String action = null;
            if ((action = (String) getOption(WSHandlerConstants.ACTION)) == null)
            {
                action = (String) msgContext.getProperty(WSHandlerConstants.ACTION);
            }
            if (action == null)
            {
                log.error("WSS4JInHandler: No action defined");
                throw new XFireRuntimeException("WSS4JInHandler: No action defined");
            }

            actions = WSSecurityUtil.decodeAction(action);

            String actor = (String) getOption(WSHandlerConstants.ACTOR);

            AbstractMessage sm = msgContext.getCurrentMessage();
            Document doc = (Document) sm.getProperty(DOMInHandler.DOM_MESSAGE);

            if (doc == null){
                log.error("DOMInHandler must be enabled for WS-Security!");
                throw new XFireRuntimeException("DOMInHandler must be enabled for WS-Security!");
            }

            /*
             * Check if it's a response and if its a fault. Don't process
             * faults.
             */
            if (sm.getBody() instanceof XFireFault)
                return;

            /*
             * To check a UsernameToken or to decrypt an encrypted message we
             * need a password.
             */
            CallbackHandler cbHandler = null;
            if (actions.contains(WSConstants.ENCR) || actions.contains(WSConstants.UT))
            {
                cbHandler = getPasswordCallbackHandler(reqData);
            }

            /*
             * Get and check the Signature specific parameters first because
             * they may be used for encryption too.
             */
            doReceiverAction(actions, reqData);

            WSHandlerResult wsResult = null;
            if (tlog.isDebugEnabled())
            {
                t1 = System.currentTimeMillis();
            }

            try
            {
                wsResult = secEngine.processSecurityHeader(doc, actor, cbHandler, reqData
                        .getSigVerCrypto(), reqData.getDecCrypto());
            }
            catch (WSSecurityException ex)
            {
            	log.error(ex);
                throw new XFireFault("WSS4JInHandler: security processing failed", ex,
                        XFireFault.SENDER);
            }

            if (tlog.isDebugEnabled())
            {
                t2 = System.currentTimeMillis();
            }

            if (wsResult == null)
            { // no security header found
                if (actions.contains(WSConstants.NO_SECURITY))
                {
                    return;
                }
                else
                {
                    log.error("WSS4JInHandler: Request does not contain required Security header");
                    throw new XFireFault(
                            "WSS4JInHandler: Request does not contain required Security header",
                            XFireFault.SENDER);
                }
            }

            if (reqData.isEnableSignatureConfirmation())
            {
                checkSignatureConfirmation(reqData, wsResult);
            }

            /*
             * now check the security actions: do they match, in right order?
             */
            if (!checkReceiverResults(wsResult.getResults(), actions))
            {
                log.error("WSS4JInHandler: security processing failed (actions mismatch)");
                throw new XFireFault(
                        "WSS4JInHandler: security processing failed (actions mismatch)",
                        XFireFault.SENDER);

            }
            /*
             * All ok up to this point. Now construct and setup the security
             * result structure. The service may fetch this and check it.
             */
            List<WSHandlerResult> results = null;
            if ((results = (List<WSHandlerResult>) msgContext.getProperty(WSHandlerConstants.RECV_RESULTS)) == null)
            {
                results = new ArrayList<WSHandlerResult>();
                msgContext.setProperty(WSHandlerConstants.RECV_RESULTS, results);
            }
            WSHandlerResult rResult = new WSHandlerResult(actor, wsResult.getResults(), wsResult.getActionResults());
            results.add(0, rResult);
            if (tlog.isDebugEnabled())
            {
                t4 = System.currentTimeMillis();
                tlog.debug("Receive request: total= " + (t4 - t0) + " request preparation= "
                        + (t1 - t0) + " request processing= " + (t2 - t1) + " request to Axis= "
                        + (t3 - t2) + " header, cert verify, timestamp= " + (t4 - t3) + "\n");
            }

            if (doDebug)
            {
                log.debug("WSS4JInHandler: exit invoke()");
            }
        }
        catch (WSSecurityException e)
        {
            log.error(e);
        }
        finally
        {
            reqData = null;
        }
    }
}
