package controllers;

import com.dropbox.core.*;
import play.Logger;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import views.html.done;
import views.html.index;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class Application extends Controller {

    private static DbxWebAuth webAuth;
    static Logger.ALogger log = play.Logger.of("Sample");

    public static Result index() {
        return ok(index.render());
    }

    public static Result getFlow() {
        final String APP_KEY = "";
        final String APP_SECRET = "";
        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);

        DbxRequestConfig config = new DbxRequestConfig(
                "Webhooks sample", Locale.getDefault().toString());

        String sessionKey = java.util.UUID.randomUUID().toString();
        Map<String, String> sessionMap = new HashMap<>();
        Http.Session session = new Http.Session(sessionMap);
        String redirectUrl = "";
        if (Http.Context.current().request().host().startsWith("127.0.0.1")) {
            redirectUrl = routes.Application.oAuthCallBack().
                    absoluteURL(Http.Context.current().request());
        }
        else {
            redirectUrl = routes.Application.oAuthCallBack().
                    absoluteURL(Http.Context.current().request(), true);
        }
        DbxSessionStore csrfSessionStore = new DbxPlaySessionStore(session,sessionKey);
        webAuth = new DbxWebAuth(config,appInfo,redirectUrl,csrfSessionStore);
        return redirect(webAuth.start());
    }

    public static Result oAuthCallBack() {
        DbxAuthFinish authFinish;
        try {
            authFinish = webAuth.finish(Http.Context.current().request().queryString());
        }
        catch (DbxWebAuth.BadRequestException ex) {
            log.error("On /dropbox-auth-finish: Bad request: " + ex.getMessage());
            return status(400, " Bad request.");
        }
        catch (DbxWebAuth.BadStateException ex) {
            // Send them back to the start of the auth flow.
            log.info("Bad state exception. Redirecting again.");
            String redirectUrl = "";
            if (Http.Context.current().request().host().startsWith("127.0.0.1")) {
                redirectUrl = routes.Application.oAuthCallBack().
                        absoluteURL(Http.Context.current().request());
            }
            else {
                redirectUrl = routes.Application.oAuthCallBack().
                        absoluteURL(Http.Context.current().request(), true);
            }
            return redirect(redirectUrl);
        }
        catch (DbxWebAuth.CsrfException ex) {
            log.error("On /dropbox-auth-finish: CSRF mismatch: " + ex.getMessage());
            return notFound();
        }
        catch (DbxWebAuth.NotApprovedException ex) {
            // When Dropbox asked "Do you want to allow this app to access your
            // Dropbox account?", the user clicked "No".
            return unauthorized();
        }
        catch (DbxWebAuth.ProviderException ex) {
            log.error("On /dropbox-auth-finish: Auth failed: " + ex.getMessage());
            return status(503, "Error communicating with Dropbox.");
        }
        catch (DbxException ex) {
            log.error("On /dropbox-auth-finish: Error getting token: " + ex.getMessage());
            return status(503, "Error communicating with Dropbox.");
        }
        String accessToken = authFinish.accessToken;
        String uid = authFinish.userId;
        String urlState = authFinish.urlState;

        //todo: store the values in redis

        return ok(done.render()); //todo change this
    }

    public static Result echoChallenge() {
        return play.mvc.Results.TODO;
    }

    public static Result performWebHookTask() {
        return play.mvc.Results.TODO;
    }

    public static Result done() {
        return ok(done.render());
    }

    private boolean validateRequest() {
        return true;
    }
}
