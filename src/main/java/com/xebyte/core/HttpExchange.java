package com.xebyte.core;

import com.sun.net.httpserver.Headers;

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.URI;

/**
 * Transport-agnostic HTTP exchange interface.
 */
public interface HttpExchange extends Closeable {
    String getRequestMethod();
    URI getRequestURI();
    Headers getRequestHeaders();
    InputStream getRequestBody();
    Headers getResponseHeaders();
    void sendResponseHeaders(int code, long length) throws IOException;
    OutputStream getResponseBody();
}
