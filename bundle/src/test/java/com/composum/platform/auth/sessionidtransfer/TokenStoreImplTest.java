package com.composum.platform.auth.sessionidtransfer;

import com.composum.sling.platform.testing.testutil.ErrorCollectorAlwaysPrintingFailures;
import org.apache.commons.lang3.tuple.Pair;
import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.Test;

import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

/** Tests for {@link TokenStoreImpl}. */
public class TokenStoreImplTest {

    @Rule
    public final ErrorCollectorAlwaysPrintingFailures ec = new ErrorCollectorAlwaysPrintingFailures();

    protected Map<String, Pair<Long, Object>> storealias;

    TokenStoreImpl store = new TokenStoreImpl() {{
        storealias = store;
    }};

    @Test
    public void storeAndRetrieve() {
        Object stored = new Object();
        String token = store.save(stored, 1000);
        ec.checkThat(token, notNullValue());
        ec.checkThat(token.length(), is(32));
        Object retrieved = store.retrieveAndDelete(token, stored.getClass());
        ec.checkThat(retrieved, Matchers.sameInstance(stored));

        String token2 = store.save(stored, 100);
        ec.checkThat(token2, not(equalTo(token)));
    }

    @Test
    public void failingRetrieve() {
        Object stored = Integer.valueOf(35);
        String token = store.save(stored, 1000);
        ec.checkThat(token.length(), is(32));

        ec.checkThat(store.retrieveAndDelete("invalidtoken", Object.class), nullValue());

        Object retrieved = store.retrieveAndDelete(token, String.class);
        ec.checkThat(retrieved, nullValue());
    }

    @Test
    public void timeout() throws InterruptedException {
        Object stored = new Object();
        String token = store.save(stored, 200);
        Thread.sleep(100);
        ec.checkThat(store.retrieveAndDelete(token, stored.getClass()), sameInstance(stored));

        token = store.save(stored, 200);
        Thread.sleep(300);
        ec.checkThat(store.retrieveAndDelete(token, stored.getClass()), nullValue());
    }

    @Test
    public void cleanup() throws InterruptedException {
        Object stored = new Object();
        for (int i = 0; i < 10; ++i) {
            store.save(stored, 200);
        }
        ec.checkThat(storealias.size(), is(10));

        Thread.sleep(100);
        // at 100ms, other items have 100ms to time out
        for (int i = 0; i < 10; ++i) {
            store.save(stored, 200);
        }
        ec.checkThat(storealias.size(), is(20));

        Thread.sleep(150);
        // at 250ms the first items have timed out, but the others not
        store.retrieveAndDelete("bla", Object.class); // calls cleanup
        ec.checkThat(storealias.size(), is(10));

        Thread.sleep(100);
        // at 350ms all items have timed out
        store.retrieveAndDelete("bla", Object.class); // calls cleanup
        ec.checkThat(storealias.size(), is(0));
    }

}
