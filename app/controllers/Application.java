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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class Application extends Controller {

    private static Logger.ALogger log = play.Logger.of("Herioux");
    private static  DbxWebAuth webAuth ;
    private static Jedis redisClient;
    private static DbxRequestConfig dropboxConfig;

    public static Result index() {
        return ok(index.render());
    }

    static {

        String APP_KEY = "npv9f72j4ldebvg";
        String APP_SECRET = "bwc2xenbkuagiee";
        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);

        dropboxConfig = new DbxRequestConfig(
                "Sundoro", Locale.getDefault().toString());

        String sessionKey = "random-csrf-token-key";
        Map<String, String> sessionMap = new HashMap<>();
        Http.Session session = new Http.Session(sessionMap);
        String redirectUrl = "";
        if (Http.Context.current().request().host().startsWith("127.0.0.1") ||
                Http.Context.current().request().host().startsWith("localhost")) {
            redirectUrl = routes.Application.oAuthCallBack().
                    absoluteURL(Http.Context.current().request());
        }
        else {
            redirectUrl = routes.Application.oAuthCallBack().
                    absoluteURL(Http.Context.current().request(), true);
        }
        DbxSessionStore csrfSessionStore = new DbxPlaySessionStore(session,sessionKey);
        webAuth = new DbxWebAuth(dropboxConfig,appInfo,redirectUrl,csrfSessionStore);

        JedisPool pool = Play.application().plugin(RedisPlugin.class).jedisPool();
        Jedis redisClient = pool.getResource();

    }

    public static Result getFlow() {
        return redirect(webAuth.start());
    }

    public static Promise<Result> oAuthCallBack() {
        DbxAuthFinish authFinish;
        try {
            play.mvc.Http.Request request = request();
            log.info("***Request param are ****",request.toString());
            authFinish = webAuth.finish(request.queryString());
        }
        catch (DbxWebAuth.BadRequestException ex) {
            log.error("On /dropbox-auth-finish: Bad request: " + ex.getMessage());
            return Promise.pure(status(400, " Bad request."));
        }
        catch (DbxWebAuth.BadStateException ex) {
            // Send them back to the start of the auth flow.
            //todo use the same csrf key both the times
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

        redisClient.hset("tokens", uid, accessToken);

        Promise<Boolean> performConversionForUser = Promise.promise(() -> processUser(uid));


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

    private static Boolean processUser(String uid) {
        String oauthToken = redisClient.hget("tokens",uid);
        String userCursor = redisClient.hget("cursors",uid);

        DbxClient dropboxClient = new DbxClient(dropboxConfig,uid);
        boolean hasMore = true;
        DbxDelta<DbxEntry> result = null;
        while (hasMore) {
            try {
                 result = dropboxClient.getDelta(userCursor);
            } catch (DbxException e) {
                log.error("Error getting the user detail for uid : {}, cursor : {}",uid,userCursor);
                return false;
            }
            if (result != null) {
               for ( DbxDelta.Entry<DbxEntry> entry :  result.entries) {
                    if (entry.metadata == null || entry.metadata.isFolder() || !entry.lcPath.endsWith(".md")) {
                        continue;
                    }
                   String htmlContent = "Hello world"; //Replace with impl
                   File uploadFile = new File(htmlContent);
                   String fileName = entry.lcPath.substring(entry.lcPath.length()-4); //todo check this
                   fileName = fileName + ".html";
                   try (InputStream inputStream = new ByteArrayInputStream(htmlContent.getBytes())) {
                       DbxEntry.File uploadedFile = dropboxClient.uploadFile(fileName, DbxWriteMode.force(), uploadFile.length(), inputStream);
                   } catch (IOException e) {
                       log.error("IO Exception while uploading file : {} ", e);
                       return false;
                   } catch (DbxException e) {
                       log.error("DbxException while uploading file : {} ", e);
                       return false;
                   }
               }

                hasMore = result.hasMore;
            }

        }
        return true;
    }
}
