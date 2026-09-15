/* Copyright (C) 2026 jpi59. SPDX-License-Identifier: GPL-3.0-or-later */
package org.jpi59.ethicupdatesafe;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

/** Small, opt-in client for public F-Droid records. It never uploads an APK or its hash. */
final class FdroidLookup {
    static final class Result {
        final boolean published;
        final String versions;
        final String description;
        final Set<String> antiFeatures;
        final String verification;
        final String note;

        Result(boolean published, String versions, String description, Set<String> antiFeatures, String verification, String note) {
            this.published = published;
            this.versions = versions;
            this.description = description;
            this.antiFeatures = antiFeatures;
            this.verification = verification;
            this.note = note;
        }
    }

    private static final String FDROID_API = "https://f-droid.org/api/v1/packages/";
    private static final String METADATA = "https://gitlab.com/fdroid/fdroiddata/-/raw/master/metadata/";
    private static final String VERIFY = "https://verification.f-droid.org/";

    private FdroidLookup() { }

    static Result query(String packageName, long versionCode) throws Exception {
        if (packageName == null || !packageName.matches("[A-Za-z0-9_.]+")) throw new IllegalArgumentException("El identificador de paquete no es válido para una consulta pública.");
        String encoded = URLEncoder.encode(packageName, "UTF-8");
        Response api = get(FDROID_API + encoded);
        if (api.code == HttpURLConnection.HTTP_NOT_FOUND) {
            return new Result(false, "No aparece en el repositorio principal de F-Droid.", "No se consultaron metadatos porque el paquete no figura en el catálogo principal.", new LinkedHashSet<>(), "Sin registro de F-Droid.",
                    "Esto no determina si la APK es segura o insegura; sólo indica que no está publicada actualmente en el repositorio principal.");
        }
        if (api.code != HttpURLConnection.HTTP_OK) throw new IllegalStateException("F-Droid respondió HTTP " + api.code + ".");

        JSONObject object = new JSONObject(api.body);
        int suggested = object.optInt("suggestedVersionCode", -1);
        JSONArray versions = object.optJSONArray("packages");
        boolean candidateListed = false;
        int count = versions == null ? 0 : versions.length();
        if (versions != null) for (int i = 0; i < versions.length(); i++) if (versions.optJSONObject(i).optLong("versionCode", -1) == versionCode) candidateListed = true;
        String versionText = "Publicado en F-Droid: " + count + " versión(es)." + (suggested >= 0 ? " Versión sugerida: código " + suggested + "." : "")
                + (candidateListed ? " La versión seleccionada figura en el catálogo." : " La versión seleccionada no figura en el catálogo actual.");

        String metadata = "";
        Set<String> antiFeatures = new LinkedHashSet<>();
        String description = "Descripción no disponible en los metadatos consultados.";
        Response metadataResponse = get(METADATA + encoded + ".yml");
        if (metadataResponse.code == HttpURLConnection.HTTP_OK) {
            metadata = metadataResponse.body;
            String summary = scalar(metadata, "Summary");
            String fullDescription = block(metadata, "Description");
            description = fullDescription.isEmpty() ? (summary.isEmpty() ? description : summary) : fullDescription;
            antiFeatures.addAll(list(metadata, "AntiFeatures"));
        }

        Response verificationResponse = get(VERIFY + encoded + ".json");
        String verification = "No hay registro público de verificación reproducible para este paquete.";
        if (verificationResponse.code == HttpURLConnection.HTTP_OK) {
            JSONObject verificationObject = new JSONObject(verificationResponse.body);
            JSONArray reports = verificationObject.optJSONArray("apkReports");
            boolean reportForVersion = false;
            if (reports != null) for (int i = 0; i < reports.length(); i++) if (reports.optString(i).contains("_" + versionCode + ".apk.json")) reportForVersion = true;
            verification = reportForVersion ? "Hay un reporte público de verificación para esta versión." : "El paquete tiene registros públicos de verificación, pero no se encontró uno para la versión seleccionada.";
        }
        String note = "Fuentes consultadas: API pública, metadatos y verificación de F-Droid. Ausencia de Anti‑Features o de reportes no es una certificación de seguridad.";
        return new Result(true, versionText, description, antiFeatures, verification, note);
    }

    private static Response get(String address) throws Exception {
        HttpsURLConnection connection = (HttpsURLConnection) new java.net.URL(address).openConnection();
        connection.setRequestMethod("GET"); connection.setConnectTimeout(10_000); connection.setReadTimeout(10_000);
        connection.setRequestProperty("Accept", "application/json, text/plain, text/yaml");
        int code = connection.getResponseCode();
        InputStream stream = code >= 400 ? connection.getErrorStream() : connection.getInputStream();
        String body = stream == null ? "" : read(stream);
        connection.disconnect();
        return new Response(code, body);
    }

    private static String read(InputStream stream) throws Exception {
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            char[] buffer = new char[4096];
            for (int count; (count = reader.read(buffer)) != -1; ) {
                if (result.length() + count > 512_000) throw new IllegalStateException("La respuesta pública es demasiado grande.");
                result.append(buffer, 0, count);
            }
        }
        return result.toString();
    }

    private static String scalar(String yaml, String key) {
        String prefix = key + ":";
        for (String line : yaml.split("\\n")) if (line.startsWith(prefix)) return line.substring(prefix.length()).trim().replace("\"", "");
        return "";
    }

    private static String block(String yaml, String key) {
        String[] lines = yaml.split("\\n"); String prefix = key + ":"; boolean active = false; StringBuilder result = new StringBuilder();
        for (String line : lines) {
            if (!active) { if (line.startsWith(prefix)) active = true; continue; }
            if (!line.startsWith(" ") && !line.isEmpty()) break;
            String value = line.trim(); if (value.isEmpty() || value.equals("|-")) continue;
            if (result.length() > 0) result.append(' '); result.append(value);
            if (result.length() >= 500) break;
        }
        return result.toString();
    }

    private static Set<String> list(String yaml, String key) {
        String[] lines = yaml.split("\\n"); String prefix = key + ":"; boolean active = false; Set<String> result = new LinkedHashSet<>();
        for (String line : lines) {
            if (!active) { if (line.startsWith(prefix)) active = true; continue; }
            if (!line.startsWith(" ") && !line.isEmpty()) break;
            String value = line.trim(); if (value.startsWith("- ")) result.add(value.substring(2).trim());
        }
        return result;
    }

    private static final class Response { final int code; final String body; Response(int code, String body) { this.code = code; this.body = body; } }
}
