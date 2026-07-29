package com.xebyte.core;

import java.io.InputStream;
import java.util.Map;

/**
 * Declarative endpoint definition used by the local transports.
 *
 * @param path        HTTP path (e.g., "/list_functions")
 * @param method      HTTP method ("GET" or "POST")
 * @param handler     Lambda that processes the request and returns a Response
 */
public record EndpointDef(String path, String method, EndpointHandler handler,
                          Map<String, Integer> nativeByteLimits) {

    public EndpointDef {
        nativeByteLimits = nativeByteLimits == null
            ? Map.of()
            : Map.copyOf(nativeByteLimits);
    }

    /** Parse a request body using this endpoint's compact native-byte hints. */
    public Map<String, Object> parseBody(InputStream input) {
        return JsonHelper.parseBody(input, nativeByteLimits);
    }

    /** Functional interface for endpoint handlers. */
    @FunctionalInterface
    public interface EndpointHandler {
        /**
         * Handle an HTTP request.
         *
         * @param query Query parameters from the URL (GET params)
         * @param body  Parsed JSON body (POST params), empty map for GET requests
         * @return Response to send back to the client
         * @throws Exception Any exception is caught by the safe handler wrapper
         */
        Response handle(Map<String, String> query, Map<String, Object> body) throws Exception;
    }

}
