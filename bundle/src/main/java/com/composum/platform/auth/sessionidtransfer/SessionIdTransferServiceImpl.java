package com.composum.platform.auth.sessionidtransfer;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Implementation of {@link SessionIdTransferService}.
 *
 * @see SessionIdTransferService
 */
@Component(
        service = {SessionIdTransferService.class},
        property = {
                Constants.SERVICE_DESCRIPTION + "=Composum Platform Auth Session Transfer Service"
        }
)
public class SessionIdTransferServiceImpl implements SessionIdTransferService {

    private static final Logger LOG = LoggerFactory.getLogger(SessionIdTransferServiceImpl.class);

    @Reference(cardinality = ReferenceCardinality.OPTIONAL)
    protected volatile SessionIdTransferConfigurationService configurationService;

    /** Maps tokens to {@link com.composum.platform.auth.sessionidtransfer.SessionIdTransferService.TransferInfo}. */
    protected final Map<String, TransferInfo> transferInfoMap = Collections.synchronizedMap(new HashMap<>());

    /** Queue for tokens in the order of their creation time - for cleanup. */
    protected final Deque<String> tokenToDeleteQueue = new ConcurrentLinkedDeque<>();

    protected final SecureRandom tokenGenerator = new SecureRandom();

    @Nonnull
    @Override
    public String registerTransferInfo(@Nonnull TransferInfo transferInfo) {
        String token = RandomStringUtils.random(32, 0, 0, true, true, null, tokenGenerator);
        cleanup();
        tokenToDeleteQueue.addLast(token);
        transferInfoMap.put(token, transferInfo);
        LOG.debug("registerTransferInfo"); // deliberately *not* log token to prevent intrusion if logfile is accessible
        return token;
    }

    protected long getMinCreateTime() {
        SessionIdTransferConfigurationService cserv = configurationService;
        SessionIdTransferConfigurationService.SessionIdTransferConfiguration cfg = configurationService != null ? configurationService.getConfiguration() : null;
        long timeout = cfg != null ? cfg.tokenTimeout() : 5000;
        return System.currentTimeMillis() - timeout;
    }

    protected void cleanup() {
        synchronized (tokenToDeleteQueue) {
            long minCreationTime = getMinCreateTime();
            String token;
            TransferInfo transferInfo;
            token = tokenToDeleteQueue.peekFirst();
            transferInfo = token != null ? transferInfoMap.get(token) : null;
            do {
                token = tokenToDeleteQueue.pollFirst();
                if (token == null) { return; }
                transferInfo = token != null ? transferInfoMap.get(token) : null;
                if (transferInfo != null) {
                    if (transferInfo.tokenCreationTime > minCreationTime) {
                        tokenToDeleteQueue.addFirst(token); // put it back since first one isn't timed out yet, stop.
                        return;
                    } else { // timed out
                        transferInfoMap.remove(token);
                    }
                }
            } while (!tokenToDeleteQueue.isEmpty());
        }
    }

    @Nullable
    @Override
    public TransferInfo retrieveTransferInfo(@Nullable String token) {
        TransferInfo transferInfo = null;
        if (StringUtils.isNotBlank(token)) {
            transferInfo = transferInfoMap.get(token);
            if (transferInfo != null) {
                transferInfoMap.remove(token);
                // tokenToDeleteQueue is automatically cleaned after a while.
                if (transferInfo.tokenCreationTime < getMinCreateTime()) {
                    transferInfo = null;
                    LOG.info("TransferInfo timed out - discarding it.");
                } else {
                    LOG.info("Found transferinfo for token.");
                }
            }
        }
        cleanup();
        return transferInfo;
    }
}
