package com.xebyte.core;

import java.io.InputStream;
import java.util.*;

/**
 * Declarative endpoint definition for shared registration between GUI and headless modes.
 *
 * @param path        HTTP path (e.g., "/list_functions")
 * @param method      HTTP method ("GET" or "POST")
 * @param handler     Lambda that processes the request and returns a Response
 * @param description Human-readable description (for schema generation)
 * @param params      Parameter schema descriptors (for schema generation)
 */
public record EndpointDef(String path, String method, EndpointHandler handler,
                          String description, List<ParamDef> params,
                          Map<String, Integer> nativeByteLimits) {

    /** Backward-compatible constructor without schema metadata. */
    public EndpointDef(String path, String method, EndpointHandler handler) {
        this(path, method, handler, "", List.of(), Map.of());
    }

    public EndpointDef(
            String path,
            String method,
            EndpointHandler handler,
            Map<String, Integer> nativeByteLimits) {
        this(path, method, handler, "", List.of(), nativeByteLimits);
    }

    public EndpointDef(
            String path,
            String method,
            EndpointHandler handler,
            String description,
            List<ParamDef> params) {
        this(path, method, handler, description, params, Map.of());
    }

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

    /**
     * Parameter schema descriptor for schema generation.
     *
     * @param name         Parameter name
     * @param type         JSON Schema type (string, integer, boolean, number, object, array)
     * @param source       Where the param comes from (query or body)
     * @param required     Whether the parameter is required
     * @param defaultValue Default value (null if none)
     * @param description  Human-readable description
     */
    public record ParamDef(String name, String type, String source,
                           boolean required, String defaultValue, String description) {

        /** Serialize to JSON. */
        public String toJson() {
            return JsonHelper.toJson(schema());
        }

        private Map<String, Object> schema() {
            Map<String, Object> schema = new LinkedHashMap<>();
            schema.put("name", name);
            schema.put("type", type);
            schema.put("source", source);
            schema.put("required", required);
            if (defaultValue != null) {
                schema.put("default", defaultValue);
            }
            if (description != null && !description.isEmpty()) {
                schema.put("description", description);
            }
            return schema;
        }
    }

    /** Serialize endpoint schema to JSON. */
    public String schemaJson() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("path", path);
        schema.put("method", method);
        if (description != null && !description.isEmpty()) {
            schema.put("description", description);
        }
        schema.put("params", params.stream().map(ParamDef::schema).toList());
        return JsonHelper.toJson(schema);
    }
}
