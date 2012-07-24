package com.spotify.condor;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import jregex.Matcher;
import jregex.Pattern;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.net.BindException;

@Slf4j
public class SessionHandler extends AbstractHandler {
    final Pattern pathInfoPattern;
    final Pattern resetSessionPattern;
    final Pattern sessionTargetPattern;
    final String ignoredAccelRedirectPath;
    final String id;
    final String accelRedirectPath;
    final String sessionTargetSymlink;

    final Ehcache cache;

    SessionHandler(final Config cfg) {
        cache = CacheManager.create().getCache("sessions");

        pathInfoPattern = new Pattern(cfg.getString("match"));
        resetSessionPattern = new Pattern(cfg.getString("reset_on"));
        ignoredAccelRedirectPath = cfg.getString("when_ignored");
        id = cfg.getString("id");
        accelRedirectPath = cfg.getString("accel_redirect");

        final Config sessionTargetConfig = cfg.getConfig("target");
        sessionTargetSymlink = sessionTargetConfig.getString("read_symlink");
        sessionTargetPattern = new Pattern(sessionTargetConfig.getString("extract"));
    }

    @Data
    static private class SessionId {
        final String clientId;
        final String pathId;
    }

    private static void fail(Request request, HttpServletResponse resp, int code, String message) throws IOException {
        resp.setStatus(code);
        resp.getWriter().printf("%d: %s", code, message);
        request.setHandled(true);
    }

    @Override
    public void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {
        final String clientId = httpServletRequest.getHeader("X-Real-IP");
        final String pathInfo = httpServletRequest.getPathInfo();
        final String forwardPath;

        final Matcher pathInfoMatcher = pathInfoPattern.matcher(pathInfo);
        if (!pathInfoMatcher.find()) {
            log.info("Unmatched request '{}' from client {}", pathInfo, clientId);
            forwardPath = ignoredAccelRedirectPath.replaceAll("\\$\\{path\\}", pathInfo);
        } else {
            log.info("Matched request '{}' from client {}", pathInfo, clientId);

            final String pathId = pathInfoPattern.replacer(id).replace(pathInfo);
            final String sessionTarget;
            try {
                sessionTarget = getSessionTarget(clientId, pathId, pathInfo);
            } catch (IOException e) {
                log.warn("Couldn't read session symlink!");
                fail(request, httpServletResponse, HttpServletResponse.SC_GONE, "Couldn't read session symlink!");
                return;
            }
            final String tempPath = accelRedirectPath.replaceAll("\\$\\{session\\}", sessionTarget);
            forwardPath = pathInfoPattern.replacer(tempPath).replace(pathInfo);
        }
        log.info("Sending {} to '{}'", clientId, forwardPath);
        httpServletResponse.setHeader("X-Accel-Redirect", forwardPath);
        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        request.setHandled(true);
    }

    private boolean shouldResetSession(String pathInfo) {
        return resetSessionPattern.matcher(pathInfo).find();
    }

    private String extractSessionTargetFromSymlink(final String pathInfo) throws IOException {
        final String path = pathInfoPattern.replacer(sessionTargetSymlink).replace(pathInfo);
        log.debug("Looking up symlink {}", path);

        final File file = new File(path);

        if (!file.exists()) {
            log.warn("Missing file {}", path);
            throw new IOException(String.format("Missing file '%s'", path));
        }

        final String canonicalPath = file.getCanonicalPath();
        log.debug("Read value {} for symlink {}", canonicalPath, path);

        final Matcher matcher = sessionTargetPattern.matcher(canonicalPath);

        if (!matcher.matches())
            throw new IOException(String.format("Invalid symbolic link '%s'", path));

        final String sessionTarget = matcher.group(1);
        log.debug("Extracted session target {} from symlink value {}", sessionTarget, canonicalPath);

        return sessionTarget;
    }

    private String getSessionTarget(String clientId, String pathId, String pathInfo) throws IOException {
        final SessionId sessionId = new SessionId(clientId, pathId);
        final Element sessionElement = cache.get(sessionId);
        final boolean noSessionAvailable = (sessionElement == null || sessionElement.getValue() == null);

        final String sessionTarget;

        if (noSessionAvailable || shouldResetSession(pathInfo)) {
            sessionTarget = extractSessionTargetFromSymlink(pathInfo);
            log.debug("Starting session {}:{}", sessionId, sessionTarget);
            cache.put(new Element(sessionId, sessionTarget));
        } else {
            sessionTarget = (String) sessionElement.getValue();
            log.debug("Reusing session {}:{}", sessionId, sessionTarget);
        }

        return sessionTarget;
    }

    public static void main(String[] args) throws Exception {
        log.info("Loading config");
        final Config cfg = ConfigFactory.load();

        log.info("Creating server");
        Server server = new Server(cfg.getInt("http.port"));
        server.setHandler(new SessionHandler(cfg.getConfig("session")));

        try {
            log.info("Starting server");
            server.start();
            log.info("Up and running!");
            server.join();
        } catch (BindException be) {
            log.error(be.toString());
            System.exit(1);
        }
    }
}
