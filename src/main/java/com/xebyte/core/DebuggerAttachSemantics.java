package com.xebyte.core;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema;

final class DebuggerAttachSemantics {
    @FunctionalInterface
    interface ObjectResolver {
        Object resolve(TraceObjectSchema schema);
    }

    private DebuggerAttachSemantics() {}

    static TraceRmiLaunchOffer selectOffer(Collection<TraceRmiLaunchOffer> offers,
                                           String requested) {
        if (requested == null || requested.isBlank()) {
            throw new IllegalArgumentException("An exact debugger launch offer is required");
        }
        String selectedName = requested.trim();
        List<TraceRmiLaunchOffer> matches = offers.stream()
                .filter(offer -> selectedName.equalsIgnoreCase(offer.getTitle()) ||
                        selectedName.equalsIgnoreCase(offer.getConfigName()))
                .toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException("Debugger offer '" + selectedName +
                    "' matched " + matches.size() + ". Available offers: " +
                    describeOffers(offers));
        }
        return matches.get(0);
    }

    static void requireAttachOnlyOffer(TraceRmiLaunchOffer offer) {
        if (offer.requiresImage()) {
            throw new IllegalArgumentException("Debugger offer '" + offer.getTitle() +
                    "' requires an image and cannot start an attach-only session");
        }
    }

    static RemoteMethod selectAttachMethod(Collection<RemoteMethod> methods) {
        List<RemoteMethod> matches = methods.stream()
                .filter(method -> Objects.equals(method.action(), ActionName.ATTACH))
                .filter(method -> method.parameters().values().stream()
                        .filter(parameter -> parameter.type()
                                .equals(PrimitiveTraceObjectSchema.INT.getName()))
                        .count() == 1)
                .toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException("PID attach method matched " + matches.size() +
                    ". Available attach methods: " + describeMethods(methods));
        }
        return matches.get(0);
    }

    static Map<String, Object> buildArguments(RemoteMethod method,
                                              SchemaContext schemaContext,
                                              ObjectResolver currentResolver,
                                              ObjectResolver rootResolver,
                                              int pid) {
        Map<String, Object> arguments = new LinkedHashMap<>();

        for (RemoteParameter parameter : method.parameters().values()) {
            TraceObjectSchema schema = schemaContext.getSchemaOrNull(parameter.type());
            if (schema == null) {
                throw new IllegalArgumentException("No trace schema for parameter '" +
                        parameter.name() + "' (" + parameter.type() + ")");
            }
            if (parameter.type().equals(PrimitiveTraceObjectSchema.INT.getName())) {
                arguments.put(parameter.name(), pid);
                continue;
            }
            if (schema.getType() == TraceObject.class) {
                Object object = currentResolver.resolve(schema);
                if (object == null) {
                    object = rootResolver.resolve(schema);
                }
                if (object != null) {
                    arguments.put(parameter.name(), object);
                    continue;
                }
            }
            if (!parameter.required()) {
                Object defaultValue = parameter.getDefaultValue();
                if (defaultValue != null) {
                    arguments.put(parameter.name(), defaultValue);
                }
                continue;
            }
            throw new IllegalArgumentException("Cannot resolve required attach parameter '" +
                    parameter.name() + "' (" + parameter.type() + ") from the new trace");
        }

        method.validate(arguments);
        return Collections.unmodifiableMap(arguments);
    }

    private static String describeOffers(Collection<TraceRmiLaunchOffer> offers) {
        return offers.stream()
                .map(offer -> offer.getTitle() + " [" + offer.getConfigName() + "]")
                .sorted()
                .reduce((left, right) -> left + ", " + right)
                .orElse("none");
    }

    private static String describeMethods(Collection<RemoteMethod> methods) {
        return methods.stream()
                .filter(method -> Objects.equals(method.action(), ActionName.ATTACH))
                .map(method -> method.name() + method.parameters().values().stream()
                        .map(RemoteParameter::type)
                        .map(Object::toString)
                        .sorted()
                        .toList())
                .sorted()
                .reduce((left, right) -> left + ", " + right)
                .orElse("none");
    }
}
