// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.cvss;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.srmaximus.burpfm.model.CvssResult;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class Cvss40Calculator {
    private static final int MAX_VECTOR_LENGTH = 2_048;
    private static final List<String> SCRIPTS = List.of(
            "/cvss/metrics.js",
            "/cvss/cvss_lookup.js",
            "/cvss/max_composed.js",
            "/cvss/max_severity.js",
            "/cvss/cvss_score.js",
            "/cvss/bfm_wrapper.js");

    private final String source;
    private final ObjectMapper mapper = new ObjectMapper();

    public Cvss40Calculator() {
        this.source = loadSource();
    }

    public CvssResult calculate(String rawVector) {
        String vector = rawVector == null ? "" : rawVector.trim();
        if (vector.isBlank()) {
            return CvssResult.invalid(vector, "CVSS vector is empty");
        }
        if (vector.length() > MAX_VECTOR_LENGTH || vector.indexOf('\n') >= 0 || vector.indexOf('\r') >= 0) {
            return CvssResult.invalid(vector, "CVSS vector is too long or contains line breaks");
        }

        Context context = Context.enter();
        try {
            context.setLanguageVersion(Context.VERSION_ES6);
            context.setInterpretedMode(true);
            context.setMaximumInterpreterStackDepth(1_000);
            context.setClassShutter(className -> false);
            Scriptable scope = context.initSafeStandardObjects(null, false);
            context.evaluateString(scope, source, "cvss-v4-bundle.js", 1, null);
            Object candidate = ScriptableObject.getProperty(scope, "bfmCalculateJson");
            if (!(candidate instanceof Function function)) {
                return CvssResult.invalid(vector, "CVSS calculator function is unavailable");
            }
            Object raw = function.call(context, scope, scope, new Object[]{vector});
            JsonNode payload = mapper.readTree(Context.toString(raw));
            if (!payload.path("valid").asBoolean(false)) {
                return CvssResult.invalid(vector, payload.path("error").asText("Invalid CVSS vector"));
            }
            double score = payload.path("score").asDouble();
            return new CvssResult("4.0", vector, score, severity(score), true, "");
        } catch (RuntimeException | IOException exception) {
            return CvssResult.invalid(vector, "CVSS calculation failed: " + safeMessage(exception));
        } finally {
            Context.exit();
        }
    }

    private static String severity(double score) {
        if (score == 0.0d) {
            return "None";
        }
        if (score < 4.0d) {
            return "Low";
        }
        if (score < 7.0d) {
            return "Medium";
        }
        if (score < 9.0d) {
            return "High";
        }
        return "Critical";
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }

    private static String loadSource() {
        StringBuilder builder = new StringBuilder(96_000);
        for (String resource : SCRIPTS) {
            try (InputStream input = Cvss40Calculator.class.getResourceAsStream(resource)) {
                if (input == null) {
                    throw new IllegalStateException("Missing CVSS resource " + resource);
                }
                builder.append(new String(input.readAllBytes(), StandardCharsets.UTF_8)).append('\n');
            } catch (IOException exception) {
                throw new IllegalStateException("Cannot load CVSS resource " + resource, exception);
            }
        }
        return builder.toString();
    }
}
