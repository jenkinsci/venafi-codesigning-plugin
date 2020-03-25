package io.jenkins.plugins.venafinextgencodesigning;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import hudson.model.Run;

public class LockManager {
    private Map<String, String> locks = new HashMap<>();

    public void lock(Logger logger, Run<?, ?> run, String key)
        throws IOException, InterruptedException
    {
        synchronized(locks) {
            String prevLockHolder;
            do {
                logger.log("Trying to acquire lock with key '%s'", key);
                prevLockHolder = locks.putIfAbsent(key, run.toString());
                if (prevLockHolder != null) {
                    logger.log("Lock is already held by [%s], waiting...", prevLockHolder);
                    locks.wait();
                    logger.log("Lock has been released. Trying again.");
                }
            } while (prevLockHolder != null);
        }

        logger.log("Lock successfully acquired.");
    }

    public void unlock(Logger logger, String key) {
        logger.log("Releasing lock with key '%s'", key);
        synchronized(locks) {
            locks.remove(key);
            locks.notifyAll();
        }
    }
}
