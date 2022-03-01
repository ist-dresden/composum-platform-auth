package com.composum.platform.slingsaml.setup;

import com.composum.sling.core.service.RepositorySetupService;
import com.composum.sling.core.setup.util.SetupUtil;
import org.apache.jackrabbit.vault.packaging.InstallContext;
import org.apache.jackrabbit.vault.packaging.InstallHook;
import org.apache.jackrabbit.vault.packaging.PackageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Session;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@SuppressWarnings("Duplicates")
public class SetupHook implements InstallHook {

    private static final Logger LOG = LoggerFactory.getLogger(SetupHook.class);

    private static final String CONFIG_ACL = "/conf/composum/platform/slingsaml/acl";
    private static final String SLINGSAML_ACLS = CONFIG_ACL + "/service.json";
    private static final String EXTERNAL_ACLS = CONFIG_ACL + "/external.json";

    public static final String PLATFORM_SYSTEM_USERS_PATH = "system/composum/platform/";

    public static final String PLATFORM_SLINGSAML_USER = "composum-platform-slingsaml";

    public static final String PLATFORM_GROUPS_PATH = "composum/platform/";

    public static final Map<String, List<String>> PLATFORM_USERS;
    public static final Map<String, List<String>> PLATFORM_SYSTEM_USERS;
    public static final Map<String, List<String>> PLATFORM_GROUPS;

    static {
        PLATFORM_USERS = new LinkedHashMap<>();
        PLATFORM_SYSTEM_USERS = new LinkedHashMap<>();
        PLATFORM_SYSTEM_USERS.put(PLATFORM_SYSTEM_USERS_PATH + PLATFORM_SLINGSAML_USER, Collections.emptyList());
        PLATFORM_GROUPS = new LinkedHashMap<>();
        PLATFORM_GROUPS.put(PLATFORM_GROUPS_PATH + "composum-platform-external", Collections.emptyList());
        PLATFORM_GROUPS.put(PLATFORM_GROUPS_PATH + "composum-platform-user",
                Collections.singletonList("composum-platform-external"));
    }

    @Override
    public void execute(InstallContext ctx) throws PackageException {
        switch (ctx.getPhase()) {
            case PREPARE:
                LOG.info("prepare: execute...");
                SetupUtil.setupGroupsAndUsers(ctx, PLATFORM_GROUPS, PLATFORM_SYSTEM_USERS, PLATFORM_USERS);
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
        RepositorySetupService setupService = SetupUtil.getService(RepositorySetupService.class);
        try {
            Session session = ctx.getSession();
            setupService.addJsonAcl(session, SLINGSAML_ACLS, null);
            setupService.addJsonAcl(session, EXTERNAL_ACLS, null);
            session.save();
        } catch (Exception rex) {
            LOG.error(rex.getMessage(), rex);
            throw new PackageException(rex);
        }
    }
}
