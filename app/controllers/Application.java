package controllers;

import com.dropbox.core.*;
import com.typesafe.plugin.RedisPlugin;
import play.Logger;
import play.Play;
import play.libs.F.Promise;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import views.html.done;
import views.html.index;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class Application extends Controller {

    private static Logger.ALogger log = play.Logger.of("Herioux");

    public static Result index() {
        return ok(index.render());
    }

    private static DbxWebAuth getDropboxWebAuth() {
        String APP_KEY = "npv9f72j4ldebvg";
        String APP_SECRET = "bwc2xenbkuagiee";
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
        return new DbxWebAuth(config,appInfo,redirectUrl,csrfSessionStore);
    }

    public static Result getFlow() {
        return redirect(getDropboxWebAuth().start(routes.Application.oAuthCallBack().url()));
    }

    public static Promise<Result> oAuthCallBack() {
        DbxAuthFinish authFinish;
        try {
            authFinish = getDropboxWebAuth().finish(Http.Context.current().request().queryString());
        }
        catch (DbxWebAuth.BadRequestException ex) {
            log.error("On /dropbox-auth-finish: Bad request: " + ex.getMessage());
            return Promise.pure(status(400, " Bad request."));
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
            return Promise.pure(redirect(redirectUrl));
        }
        catch (DbxWebAuth.CsrfException ex) {
            log.error("On /dropbox-auth-finish: CSRF mismatch: " + ex.getMessage());
            return Promise.pure(notFound());
        }
        catch (DbxWebAuth.NotApprovedException ex) {
            // When Dropbox asked "Do you want to allow this app to access your
            // Dropbox account?", the user clicked "No".
            return Promise.pure(unauthorized());
        }
        catch (DbxWebAuth.ProviderException ex) {
            log.error("On /dropbox-auth-finish: Auth failed: " + ex.getMessage());
            return Promise.pure(status(503, "Error communicating with Dropbox."));
        }
        catch (DbxException ex) {
            log.error("On /dropbox-auth-finish: Error getting token: " + ex.getMessage());
            return Promise.pure(status(503, "Error communicating with Dropbox."));
        }
        String accessToken = authFinish.accessToken;
        String uid = authFinish.userId;
        String urlState = authFinish.urlState;

        //todo: store the values in redis

        JedisPool pool = Play.application().plugin(RedisPlugin.class).jedisPool();
        Jedis jedis = pool.getResource();

        jedis.hset("tokens",uid,accessToken);

        Promise<Boolean> performConversionForUser = Promise.promise(() -> processUser(uid,jedis));

        // resultPromise.

        /*

        Promise<Result> exception1 =  resultPromise.recover(new Function<Throwable, Result>() {
            @Override
            public Result apply(Throwable throwable) throws Throwable {
                return null;
            }
        });
*/
        //Promise<Void> performConversionForUser = //Promise.promise((uid) -> processUser(uid));
        //now need to use akka to process user data, get the delta
        //process(uid);

        return performConversionForUser.map(aBoolean -> {
            if (aBoolean) {
                return ok(done.render());
            }
            else {
                return Results.TODO;
            }
        }); //todo change this
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

    private Boolean validateRequest() {
        return true;
    }

    private static Boolean processUser(String uid, Jedis jedis) {
        return true;
    }
}
