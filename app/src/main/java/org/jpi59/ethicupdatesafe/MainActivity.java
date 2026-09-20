/* Copyright (C) 2026 jpi59. SPDX-License-Identifier: GPL-3.0-or-later */
package org.jpi59.ethicupdatesafe;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Local APK review UI that can explicitly hand a reviewed file to Android's installer. */
public final class MainActivity extends Activity {
    private static final int PICK_APK = 20;
    private static final int INK = Color.rgb(23, 34, 30);
    private static final int MUTED = Color.rgb(86, 98, 92);
    private static final int SURFACE = Color.rgb(247, 248, 244);
    private static final int CARD = Color.WHITE;
    private static final int PRIMARY = Color.rgb(23, 107, 90);
    private static final int SAFE = Color.rgb(23, 107, 90);
    private static final int CAUTION = Color.rgb(154, 91, 8);
    private static final int RISK = Color.rgb(180, 35, 24);

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private Button selectButton;
    private TextView liveStatus;
    private LinearLayout resultCard, rows;
    private TextView verdict, explanation;
    private FdroidLookup.Result fdroidResult;
    // Kept only for the active screen so Android's installer can read the user-selected file.
    private Uri currentApkUri;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(SURFACE);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        buildUi();
    }

    @Override public void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(SURFACE);
        LinearLayout root = column();
        int side = dp(getResources().getConfiguration().screenWidthDp >= 700 ? 64 : 22);
        root.setPadding(side, dp(28), side, dp(28));
        scroll.addView(root);

        LinearLayout topBar = new LinearLayout(this);
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setGravity(Gravity.CENTER_VERTICAL);
        topBar.setPadding(0, 0, 0, dp(8));

        android.widget.ImageButton btnMenu = new android.widget.ImageButton(this);
        btnMenu.setImageResource(R.drawable.ic_settings_menu);
        btnMenu.setBackground(null);
        btnMenu.setColorFilter(PRIMARY);
        btnMenu.setContentDescription(getString(R.string.menu_title));
        btnMenu.setOnClickListener(v -> EthicEcosystemMenu.show(this, false));
        topBar.addView(btnMenu, new LinearLayout.LayoutParams(dp(44), dp(44)));

        TextView eyebrow = text("ANALIZA ANTES DE INSTALAR", 12, PRIMARY); eyebrow.setLetterSpacing(.12f); bold(eyebrow);
        LinearLayout.LayoutParams eyebrowParams = new LinearLayout.LayoutParams(0, -2, 1f);
        eyebrowParams.setMarginStart(dp(8));
        topBar.addView(eyebrow, eyebrowParams);
        root.addView(topBar);

        TextView title = text("Ethic APK Guard", 29, INK); bold(title); title.setPadding(0, dp(7), 0, 0); root.addView(title);
        TextView subtitle = text("Comprueba una APK antes de instalarla.", 17, MUTED); subtitle.setPadding(0, dp(6), 0, dp(22)); root.addView(subtitle);

        LinearLayout privacy = card(); privacy.setOrientation(LinearLayout.HORIZONTAL); privacy.setGravity(Gravity.CENTER_VERTICAL); privacy.setBackground(round(Color.rgb(232, 245, 239), Color.rgb(193, 224, 211), 20)); privacy.setPadding(dp(16), dp(14), dp(16), dp(14));
        TextView shield = text("✓", 23, PRIMARY); shield.setGravity(Gravity.CENTER); privacy.addView(shield, new LinearLayout.LayoutParams(dp(32), dp(36)));
        TextView privacyText = text("Análisis local. No instalamos automáticamente, desinstalamos, enviamos ni conservamos tu APK.", 14, INK); privacyText.setPadding(dp(10), 0, 0, 0); privacyText.setLineSpacing(dp(2), 1f); privacy.addView(privacyText, new LinearLayout.LayoutParams(0, -2, 1f));
        root.addView(privacy, fullMargins(0, 0, 0, 18));

        selectButton = new Button(this); selectButton.setText("Elegir una APK"); selectButton.setTextSize(16); selectButton.setTextColor(Color.WHITE); selectButton.setAllCaps(false); bold(selectButton); selectButton.setContentDescription("Elegir una APK para analizar sin instalarla"); selectButton.setBackground(round(PRIMARY, PRIMARY, 18)); selectButton.setOnClickListener(v -> pickApk());
        root.addView(selectButton, fullMargins(0, 0, 0, 8));
        liveStatus = text("Selecciona una APK desde el selector de archivos de Android.", 13, MUTED); liveStatus.setGravity(Gravity.CENTER); liveStatus.setPadding(0, dp(5), 0, dp(18)); root.addView(liveStatus);

        resultCard = card(); resultCard.setVisibility(View.GONE); resultCard.setPadding(dp(18), dp(18), dp(18), dp(18));
        verdict = text("", 21, INK); bold(verdict); resultCard.addView(verdict);
        explanation = text("", 15, MUTED); explanation.setLineSpacing(dp(3), 1f); explanation.setPadding(0, dp(8), 0, dp(12)); resultCard.addView(explanation);
        View line = new View(this); line.setBackgroundColor(Color.rgb(224, 230, 226)); resultCard.addView(line, new LinearLayout.LayoutParams(-1, dp(1)));
        rows = column(); rows.setPadding(0, dp(8), 0, 0); resultCard.addView(rows);
        root.addView(resultCard, fullMargins(0, 0, 0, 18));

        LinearLayout limits = card(); limits.setPadding(dp(18), dp(16), dp(18), dp(16));
        TextView limitsTitle = text("Qué comprueba", 16, INK); bold(limitsTitle); limits.addView(limitsTitle);
        TextView limitsText = text("Paquete, versión, certificado, historial de firma declarado, Android mínimo, bibliotecas nativas, código DEX y permisos sensibles nuevos. Reconoce paquetes divididos, pero sólo instala APK únicas. Android conserva la decisión final.", 14, MUTED); limitsText.setLineSpacing(dp(3), 1f); limitsText.setPadding(0, dp(7), 0, 0); limits.addView(limitsText);
        root.addView(limits);
        setContentView(scroll);
    }

    private void pickApk() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        // Some document providers label APK files as generic binary data. The analyzer still
        // rejects anything that is not a valid APK, so a broad picker is safer than hiding it.
        intent.setType("*/*");
        startActivityForResult(intent, PICK_APK);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_APK || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        currentApkUri = uri;
        selectButton.setEnabled(false);
        liveStatus.setText("Analizando localmente…");
        resultCard.setVisibility(View.GONE);
        executor.execute(() -> {
            try {
                File apk = new File(getCacheDir(), "selected.apk");
                try {
                    ApkAnalyzer.copyToFile(this, uri, apk);
                    ApkAnalyzer.Result result = ApkAnalyzer.analyze(this, apk);
                    runOnUiThread(() -> showResult(result));
                } finally {
                    // The result contains the facts needed by the UI; retaining the APK is not needed.
                    if (apk.exists() && !apk.delete()) apk.deleteOnExit();
                }
            } catch (Exception error) {
                currentApkUri = null;
                runOnUiThread(() -> showError(error.getMessage()));
            }
        });
    }

    private void showResult(ApkAnalyzer.Result result) {
        fdroidResult = null;
        selectButton.setEnabled(true);
        liveStatus.setText("Análisis terminado. La APK no fue instalada.");
        verdict.setText(result.headline);
        verdict.setTextColor(colorFor(result.verdict));
        explanation.setText(result.explanation);
        rows.removeAllViews();
        addRow("Paquete", result.packageName == null ? "No disponible" : result.packageName);
        addRow("APK elegida", result.candidateVersion);
        addRow("Instalada", result.installedVersion);
        addRow("Firma de APK", result.signer);
        addRow("Bibliotecas", result.architecture);
        if (!result.addedDangerousPermissions.isEmpty()) addRow("Permisos sensibles nuevos", join(result.addedDangerousPermissions));
        if (!result.securityChanges.isEmpty()) addRow("Impacto de seguridad", join(result.securityChanges));
        addInstallAction(result);
        Button share = new Button(this); share.setText("Compartir informe técnico"); share.setTextColor(PRIMARY); share.setAllCaps(false); share.setTextSize(14); share.setContentDescription("Compartir un resumen técnico, sin la APK"); share.setBackground(round(Color.WHITE, Color.rgb(193, 224, 211), 16)); share.setOnClickListener(v -> confirmShare(result));
        rows.addView(share, fullMargins(0, 8, 0, 0));
        if (result.packageName != null && versionCode(result) >= 0) {
            Button lookup = new Button(this); lookup.setText("Consultar datos públicos de F-Droid"); lookup.setTextColor(PRIMARY); lookup.setAllCaps(false); lookup.setTextSize(14); lookup.setContentDescription("Consultar F-Droid mediante una conexión opcional"); lookup.setBackground(round(Color.WHITE, Color.rgb(193, 224, 211), 16)); lookup.setOnClickListener(v -> confirmFdroidLookup(result, lookup));
            rows.addView(lookup, fullMargins(0, 6, 0, 0));
        }
        resultCard.setVisibility(View.VISIBLE);
    }

    private void addInstallAction(ApkAnalyzer.Result result) {
        if (currentApkUri == null || result.verdict == ApkAnalyzer.Verdict.INVALID) return;
        if (result.verdict == ApkAnalyzer.Verdict.REPLACE) {
            Button blocked = new Button(this); blocked.setText("Actualización bloqueada por firma distinta"); blocked.setAllCaps(false); blocked.setTextSize(14); blocked.setEnabled(false);
            rows.addView(blocked, fullMargins(0, 8, 0, 0));
            return;
        }
        String label = result.verdict == ApkAnalyzer.Verdict.NEW_APP ? "Instalar como aplicación distinta" : "Abrir instalador de Android";
        Button install = new Button(this); install.setText(label); install.setTextColor(Color.WHITE); install.setAllCaps(false); install.setTextSize(15); install.setContentDescription("Pedir a Android que instale la APK analizada"); install.setBackground(round(PRIMARY, PRIMARY, 16)); install.setOnClickListener(v -> confirmInstall(result));
        rows.addView(install, fullMargins(0, 8, 0, 0));
    }

    private void confirmInstall(ApkAnalyzer.Result result) {
        String warning;
        if (result.verdict == ApkAnalyzer.Verdict.NEW_APP) {
            warning = "Esta APK no actualiza una app existente: Android la tratará como una aplicación distinta y tendrá sus propios datos.";
        } else if (result.verdict == ApkAnalyzer.Verdict.CAUTION) {
            warning = "Hay una advertencia en el informe. Android puede rechazar la instalación o requerir una decisión adicional.";
        } else {
            warning = "La compatibilidad parece adecuada según el análisis local, pero Android conserva la decisión final.";
        }
        new AlertDialog.Builder(this)
                .setTitle("Abrir instalador de Android")
                .setMessage(warning + "\n\nEthic APK Guard no instalará nada por sí sola. A continuación se abrirá la pantalla oficial de Android, donde podrás cancelar o confirmar.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Continuar", (dialog, which) -> openSystemInstaller())
                .show();
    }

    private void openSystemInstaller() {
        if (currentApkUri == null) { liveStatus.setText("La selección ya no está disponible. Elige la APK otra vez."); return; }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !getPackageManager().canRequestPackageInstalls()) {
            new AlertDialog.Builder(this)
                    .setTitle("Permiso de fuente de instalación")
                    .setMessage("Android requiere permitir que Ethic APK Guard solicite una instalación. Esto no habilita instalaciones silenciosas: Android seguirá mostrando la confirmación final.")
                    .setNegativeButton("Cancelar", null)
                    .setPositiveButton("Abrir ajustes", (dialog, which) -> startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + getPackageName()))))
                    .show();
            return;
        }
        Intent install = new Intent(Intent.ACTION_VIEW);
        install.setDataAndType(currentApkUri, "application/vnd.android.package-archive");
        install.setClipData(ClipData.newRawUri("APK analizada", currentApkUri));
        install.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            startActivity(install);
            liveStatus.setText("El instalador de Android decidirá el siguiente paso.");
        } catch (Exception error) {
            liveStatus.setText("Android no pudo abrir el instalador: " + safeMessage(error));
        }
    }

    private void showError(String message) {
        selectButton.setEnabled(true);
        liveStatus.setText("No se pudo analizar la selección.");
        verdict.setText("No se pudo leer la APK"); verdict.setTextColor(RISK);
        explanation.setText(message == null ? "El archivo no pudo abrirse mediante Android." : message);
        rows.removeAllViews();
        resultCard.setVisibility(View.VISIBLE);
    }

    private void confirmShare(ApkAnalyzer.Result result) {
        new AlertDialog.Builder(this)
                .setTitle("Compartir informe técnico")
                .setMessage("Se compartirá el identificador de paquete, versiones, firma abreviada y cambios detectados. No se comparte la APK ni una lista de tus aplicaciones.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Elegir destino", (dialog, which) -> {
                    Intent send = new Intent(Intent.ACTION_SEND); send.setType("text/plain"); send.putExtra(Intent.EXTRA_TEXT, report(result));
                    startActivity(Intent.createChooser(send, "Compartir informe"));
                }).show();
    }

    private void confirmFdroidLookup(ApkAnalyzer.Result result, Button lookup) {
        new AlertDialog.Builder(this)
                .setTitle("Consultar fuentes públicas")
                .setMessage("Se enviarán por HTTPS a F-Droid y su repositorio público el identificador " + result.packageName + " y el código de versión " + versionCode(result) + ". No se envía la APK, su contenido, su hash ni una lista de aplicaciones. Los servidores pueden registrar la consulta.")
                .setNegativeButton("Cancelar", null)
                .setPositiveButton("Consultar", (dialog, which) -> {
                    lookup.setEnabled(false); selectButton.setEnabled(false); liveStatus.setText("Consultando registros públicos de F-Droid…");
                    executor.execute(() -> {
                        try {
                            FdroidLookup.Result online = FdroidLookup.query(result.packageName, versionCode(result));
                            runOnUiThread(() -> showFdroidResult(online, lookup));
                        } catch (Exception error) {
                            runOnUiThread(() -> { selectButton.setEnabled(true); lookup.setEnabled(true); liveStatus.setText("No se pudo consultar F-Droid: " + safeMessage(error)); });
                        }
                    });
                }).show();
    }

    private void showFdroidResult(FdroidLookup.Result online, Button lookup) {
        fdroidResult = online; selectButton.setEnabled(true); lookup.setEnabled(false); lookup.setText("Consulta pública de F-Droid terminada");
        liveStatus.setText("Consulta terminada. La APK no fue enviada ni instalada.");
        addRow("F-Droid", online.versions);
        addRow("Descripción pública", online.description);
        if (!online.antiFeatures.isEmpty()) addRow("Anti‑Features declarados", join(online.antiFeatures));
        else addRow("Anti‑Features declarados", "No se declararon en los metadatos consultados; esto no certifica seguridad.");
        addRow("Verificación reproducible", online.verification);
        addRow("Límite de la consulta", online.note);
    }

    private String report(ApkAnalyzer.Result result) {
        return "Informe de Ethic APK Guard\n\nResultado: " + result.headline + "\n" + result.explanation
                + "\n\nPaquete: " + result.packageName + "\nAPK: " + result.candidateVersion + "\nInstalada: " + result.installedVersion
                + "\nFirma de APK: " + result.signer + "\nBibliotecas: " + result.architecture
                + (result.addedDangerousPermissions.isEmpty() ? "" : "\nPermisos sensibles nuevos: " + join(result.addedDangerousPermissions))
                + (result.securityChanges.isEmpty() ? "" : "\nImpacto de seguridad: " + join(result.securityChanges))
                + (fdroidResult == null ? "" : "\n\nDatos públicos de F-Droid\n" + fdroidResult.versions + "\nDescripción: " + fdroidResult.description + "\nAnti‑Features: " + (fdroidResult.antiFeatures.isEmpty() ? "ninguno declarado; no es una certificación" : join(fdroidResult.antiFeatures)) + "\n" + fdroidResult.verification + "\n" + fdroidResult.note)
                + "\n\nEl análisis es local y no sustituye la decisión final de Android.";
    }

    private long versionCode(ApkAnalyzer.Result result) {
        int marker = result.candidateVersion.lastIndexOf("código ");
        if (marker < 0) return -1;
        try { return Long.parseLong(result.candidateVersion.substring(marker + 7).trim()); }
        catch (NumberFormatException ignored) { return -1; }
    }

    private String safeMessage(Exception error) { return error.getMessage() == null ? "error de red o de formato" : error.getMessage(); }

    private void addRow(String label, String value) {
        LinearLayout row = new LinearLayout(this); row.setOrientation(LinearLayout.VERTICAL); row.setPadding(0, dp(8), 0, dp(8));
        TextView key = text(label.toUpperCase(), 11, MUTED); key.setLetterSpacing(.08f); bold(key); row.addView(key);
        TextView detail = text(value, 14, INK); detail.setTextIsSelectable(true); detail.setPadding(0, dp(3), 0, 0); row.addView(detail);
        rows.addView(row);
    }

    private int colorFor(ApkAnalyzer.Verdict verdict) {
        switch (verdict) { case SAFE: return SAFE; case REPLACE: case INVALID: return RISK; default: return CAUTION; }
    }

    private LinearLayout column() { LinearLayout view = new LinearLayout(this); view.setOrientation(LinearLayout.VERTICAL); return view; }
    private LinearLayout card() { LinearLayout view = column(); view.setBackground(round(CARD, Color.rgb(225, 231, 227), 22)); return view; }
    private TextView text(String value, int size, int color) { TextView view = new TextView(this); view.setText(value); view.setTextSize(size); view.setTextColor(color); view.setFontFeatureSettings("kern"); return view; }
    private void bold(TextView view) { view.setTypeface(Typeface.create("sans-serif", Typeface.BOLD)); }
    private GradientDrawable round(int fill, int stroke, int radius) { GradientDrawable drawable = new GradientDrawable(); drawable.setColor(fill); drawable.setCornerRadius(dp(radius)); drawable.setStroke(dp(1), stroke); return drawable; }
    private LinearLayout.LayoutParams fullMargins(int left, int top, int right, int bottom) { LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.setMargins(dp(left), dp(top), dp(right), dp(bottom)); return params; }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private String join(java.util.Set<String> values) { StringBuilder builder = new StringBuilder(); for (String value : values) { if (builder.length() > 0) builder.append(", "); builder.append(value); } return builder.toString(); }
}
