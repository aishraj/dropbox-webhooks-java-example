package global;

import com.dropbox.core.DbxWebAuth;
import play.Application;
import play.GlobalSettings;

public class Global extends GlobalSettings {

    private static DbxWebAuth dbxWebAuth;

    public void onStart(Application app) {
/*        if (dbxWebAuth == null) {
            dbxWebAuth = getWebAuth();
        } */
    }
/*
    private static DbxWebAuth getWebAuth() {

        String APP_KEY = "npv9f72j4ldebvg";
        String APP_SECRET = "bwc2xenbkuagiee";
        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);

        DbxRequestConfig config = new DbxRequestConfig(
                "Sundoro", Locale.getDefault().toString());

        String sessionKey = "dropbox-csrf-token";//java.util.UUID.randomUUID().toString();
        Map<String, String> sessionMap = new HashMap<>();
        Http.Session session = new Http.Session(sessionMap);
        String redirectUrl = "";
        if (Http.Context.current().request().host().startsWith("127.0.0.1")) {
            redirectUrl = controllers.routes.Application.oAuthCallBack().
                    absoluteURL(Http.Context.current().request());
        }
        else {
            redirectUrl = controllers.routes.Application.oAuthCallBack().
                    absoluteURL(Http.Context.current().request(), true);
        }
        DbxSessionStore csrfSessionStore = new DbxPlaySessionStore(session,sessionKey);
        return new DbxWebAuth(config,appInfo,redirectUrl,csrfSessionStore);
    }


    public static DbxWebAuth getDbxWebAuth() {
        if (dbxWebAuth == null) {
            dbxWebAuth = getWebAuth();
        }
        return dbxWebAuth;
    }
*/

}
