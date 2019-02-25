package com.composum.platform.auth.setup;

import com.composum.sling.core.service.RepositorySetupService;
import com.composum.sling.core.setup.util.SetupUtil;
import org.apache.jackrabbit.vault.packaging.InstallContext;
import org.apache.jackrabbit.vault.packaging.InstallHook;
import org.apache.jackrabbit.vault.packaging.PackageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import java.io.IOException;
import java.util.Collections;

import static java.util.Collections.*;

public class SetupHook implements InstallHook {

    private static final Logger LOG = LoggerFactory.getLogger(SetupHook.class);

    private static final String SETUP_ACLS = "/conf/composum/platform/auth/setup.json";

    @Override
    @SuppressWarnings({"DuplicateStringLiteralInspection"})
    public void execute(InstallContext ctx) throws PackageException {
        switch (ctx.getPhase()) {
            case PREPARE:
                LOG.info("prepare: execute...");
                SetupUtil.setupGroupsAndUsers(ctx,
                        singletonMap("composum/platform/composum-platform-auth-external", emptyList())
                        , null, null);
                LOG.info("prepare: execute ends.");
                break;
            case INSTALLED:
                LOG.info("installed: execute...");
                setupAcls(ctx);
                LOG.info("installed: execute ends.");
                break;
        }
    }

    protected void setupAcls(InstallContext ctx) throws PackageException {
        try {
            RepositorySetupService setupService = SetupUtil.getService(RepositorySetupService.class);
            Session session = ctx.getSession();
            setupService.addJsonAcl(session, SETUP_ACLS, null);
            session.save();
        } catch (RepositoryException | IOException | RuntimeException e) {
            LOG.error("" + e, e);
            throw new PackageException(e);
        }
    }
}
