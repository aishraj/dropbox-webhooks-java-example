package controllers;

import com.dropbox.core.DbxSessionStore;
import play.mvc.Http.Session;

import java.io.Serializable;

/**
 * Created by ge3k on 10/6/14.
 */
public class DbxPlaySessionStore implements Serializable, DbxSessionStore {
    public final Session session;
    public final String key;

    public DbxPlaySessionStore(Session session, String key) {
        this.session = session;
        this.key = key;
    }

    @Override
    public /*@Nullable*/String get()
    {
        Object v = session.get(key);
        if (v instanceof String) return (String) v;
        return null;
    }

    @Override
    public void set(String value)
    {
        session.put(key, value);
    }

    @Override
    public void clear()
    {
        session.remove(key);
    }
}
