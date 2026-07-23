package com.xebyte.core;

import java.lang.annotation.*;

/**
 * Declares HTTP parameter binding for an MCP tool method parameter.
 * Used by {@link AnnotationScanner} to extract and convert HTTP request
 * parameters to Java method arguments.
 *
 * <p>Type conversion is automatic based on the Java parameter type:
 * <ul>
 *   <li>{@code String} — raw string value</li>
 *   <li>{@code int} / {@code Integer} — parsed integer (Integer is nullable)</li>
 *   <li>{@code long} — parsed long</li>
 *   <li>{@code boolean} / {@code Boolean} — parsed boolean (Boolean is nullable)</li>
 *   <li>{@code double} — parsed double</li>
 *   <li>{@code Map<String,String>} — parsed string map from body</li>
 *   <li>{@code List<Map<String,String>>} — parsed map list from body</li>
 *   <li>{@code Object} — raw body value (no conversion)</li>
 * </ul>
 *
 * @since 4.3.0
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Param {

    /** No-default sentinel value. Parameters without defaults use this internally. */
    String NO_DEFAULT = "\0NONE";

    /** Parameter name as it appears in the HTTP query string or JSON body. */
    String value();

    /** Where the parameter comes from: query string or JSON body. */
    ParamSource source() default ParamSource.QUERY;

    /**
     * Default value as a string. Use for optional parameters.
     * Leave as default ({@link #NO_DEFAULT}) for required parameters.
     * Parsed according to the Java parameter type.
     */
    String defaultValue() default "\0NONE";

    /**
     * When true, the body value is serialized to a JSON string representation.
     * Handles String pass-through, List serialization, and Map serialization.
     * Only applicable when {@code source = BODY} and Java type is {@code String}.
     */
    boolean fieldsJson() default false;

    /**
     * When positive, stream a body native numeric array into a compact
     * {@code byte[]} with this maximum length before endpoint binding. String
     * values remain strings for the endpoint's hex decoder.
     */
    int nativeByteLimit() default 0;

    /** Human-readable description of this parameter. */
    String description() default "";

    /**
     * Require a body boolean to be present when it has no default and to arrive
     * as a JSON boolean rather than coercing strings, numbers, or other values.
     * This is intended for safety-sensitive mutation controls.
     */
    boolean strictBoolean() default false;

    /**
     * Require an integral JSON number and reject fractional, overflowing, or
     * string-coerced values. Wrapper types may be omitted when
     * {@link #optional()} is true.
     */
    boolean strictInteger() default false;

    /**
     * Advertise a parameter as optional even when it has no scalar default.
     * This is useful for nullable wrapper parameters where omission means
     * "leave unchanged".
     */
    boolean optional() default false;

    /**
     * Optional JSON object fragment merged into this parameter's generated
     * schema. This preserves nested arrays/unions without weakening runtime
     * binding to a JSON-encoded string.
     */
    String schemaFragment() default "";

    /**
     * Semantic type hint for this parameter, propagated to /mcp/schema.
     * Use "address" for parameters that carry memory addresses.
     * The bridge uses this to apply address sanitization before dispatch.
     */
    String paramType() default "";

    /**
     * Alternative names for this parameter. The canonical name ({@link #value()}) is advertised
     * in /mcp/schema and should be preferred by new callers. At runtime, the parameter resolver
     * accepts any alias listed here as an alternative spelling, enabling backward compatibility
     * when standardizing inconsistent parameter names across endpoints.
     *
     * <p>Example: {@code @Param(value="function_address", aliases={"address"})}
     * will accept both {@code function_address=} and {@code address=} in HTTP requests.
     *
     * <p>Resolution order:
     * <ol>
     *   <li>Canonical name ({@link #value()})</li>
     *   <li>Aliases in declaration order</li>
     *   <li>Default value (if defined) or null</li>
     * </ol>
     */
    String[] aliases() default {};
}
