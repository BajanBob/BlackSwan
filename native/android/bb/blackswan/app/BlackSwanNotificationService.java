package bb.blackswan.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * BlackSwan real-time scam guard. With the person's permission (Settings → Notification access), it checks the text of
 * incoming notifications from messaging, email and other apps — on the phone only — for links on the daily phishing list
 * and for takeover-scam tricks, and shows a warning straight away, even when BlackSwan is closed.
 * Nothing is sent anywhere, and only warnings (not messages) are kept, so BlackSwan can show them when it is opened.
 */
public class BlackSwanNotificationService extends NotificationListenerService {
    static final String PREFS = "blackswan_guard";
    static final String QUEUE = "queue";
    static final String BLOCKLIST = "phish_domains.txt";
    private static final String CHANNEL = "blackswan_scam_guard";
    private static final Pattern URL = Pattern.compile("(?i)\\b((?:https?://|www\\.)[^\\s<>\"')\\]]+|[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:com|net|org|info|top|xyz|click|link|online|site|live|shop|help|support|app|io|co|me)(?:/[^\\s<>\"')\\]]*)?)");
    private static final String[][] RULES = {
        { "(?i)\\b(any ?desk|team ?viewer|rust ?desk|ultra ?viewer|screen ?connect|quick ?assist|supremo|splashtop|ammyy)\\b", "asks you to install a remote-control app — how scammers take over devices" },
        { "(?i)(win(dows)?\\s*\\+\\s*r|powershell|mshta|paste.{0,30}(run|terminal|command))", "tells you to paste and run a command — a known hacking trick" },
        { "(?i)\\b(gift ?cards?|itunes card|google play card|steam card)\\b", "asks for gift cards — real companies never take payment this way" },
        { "(?i)\\b(share|send|give|tell|read)\\b.{0,25}\\b(code|otp|pin)\\b", "asks for a one-time code — never share it with anyone" },
        { "(?i)\\b(seed phrase|recovery phrase|private key)\\b", "asks for crypto wallet secrets" },
        { "(?i)\\b(new|updated|change(d)?)\\s+(bank|account|payment)\\s+(details|account)\\b", "changed bank details — confirm by phone on a number you already know" },
        { "(?i)\\b(approve|accept|tap yes)\\b.{0,30}\\b(sign[- ]?in|login|request|prompt)\\b", "asks you to approve a sign-in you didn't start" },
    };
    private Set<String> domains = null;
    private long loadedAt = 0;

    private Set<String> blocklist() {
        File f = new File(getFilesDir(), BLOCKLIST);
        if (domains != null && f.lastModified() <= loadedAt) return domains;
        Set<String> s = new HashSet<>();
        try (BufferedReader r = new BufferedReader(new FileReader(f))) { String l; while ((l = r.readLine()) != null) { l = l.trim(); if (!l.isEmpty()) s.add(l); } } catch (Exception ignored) { }
        domains = s; loadedAt = f.lastModified();
        return s;
    }

    private static String hostOf(String u) {
        String h = u.replaceFirst("(?i)^https?://", "").replaceFirst("^www\\.", "");
        int cut = h.length();
        for (char c : new char[] { '/', '?', '#', ':' }) { int i = h.indexOf(c); if (i >= 0 && i < cut) cut = i; }
        return h.substring(0, cut).toLowerCase(Locale.ROOT);
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        try {
            String pkg = sbn.getPackageName();
            if (pkg == null || pkg.equals(getPackageName()) || pkg.equals("android") || pkg.startsWith("com.android.systemui")) return;
            Notification n = sbn.getNotification();
            if (n == null || (n.flags & Notification.FLAG_ONGOING_EVENT) != 0) return;
            Bundle x = n.extras;
            StringBuilder sb = new StringBuilder();
            for (String k : new String[] { Notification.EXTRA_TITLE, Notification.EXTRA_TEXT, Notification.EXTRA_BIG_TEXT, Notification.EXTRA_SUB_TEXT }) {
                CharSequence cs = x.getCharSequence(k); if (cs != null) sb.append(cs).append('\n');
            }
            CharSequence[] lines = x.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);
            if (lines != null) for (CharSequence l : lines) sb.append(l).append('\n');
            String text = sb.toString();
            if (text.trim().isEmpty()) return;

            List<String> reasons = new ArrayList<>();
            List<String> urls = new ArrayList<>();
            Matcher m = URL.matcher(text);
            Set<String> bl = blocklist();
            while (m.find()) {
                String u = m.group(1); urls.add(u);
                String h = hostOf(u);
                for (String d = h; d.contains("."); d = d.substring(d.indexOf('.') + 1)) {
                    if (bl.contains(d)) { reasons.add("contains a link to " + h + ", which is on today's phishing list"); break; }
                }
                if (u.contains("@") && u.matches("(?i)^https?://[^/]*@.*")) reasons.add("contains a link that hides its real address behind '@'");
                if (h.startsWith("xn--") || h.contains(".xn--")) reasons.add("contains a look-alike web address (punycode)");
            }
            for (String[] r : RULES) if (Pattern.compile(r[0]).matcher(text).find()) reasons.add(r[1]);
            if (reasons.isEmpty()) return;

            String app = pkg;
            try { PackageManager pm = getPackageManager(); ApplicationInfo ai = pm.getApplicationInfo(pkg, 0); app = String.valueOf(pm.getApplicationLabel(ai)); } catch (Exception ignored) { }
            save(app, pkg, reasons, urls, text);
            warn(app, reasons.get(0), sbn.getId() ^ pkg.hashCode());
        } catch (Throwable ignored) { }
    }

    private void save(String app, String pkg, List<String> reasons, List<String> urls, String text) {
        try {
            SharedPreferences sp = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            JSONArray q = new JSONArray(sp.getString(QUEUE, "[]"));
            JSONObject o = new JSONObject();
            o.put("t", System.currentTimeMillis()); o.put("app", app); o.put("package", pkg);
            o.put("reasons", new JSONArray(reasons)); o.put("urls", new JSONArray(urls));
            o.put("snippet", text.length() > 240 ? text.substring(0, 240) + "…" : text);
            JSONArray out = new JSONArray(); out.put(o);
            for (int i = 0; i < q.length() && i < 49; i++) out.put(q.get(i));
            sp.edit().putString(QUEUE, out.toString()).apply();
        } catch (Exception ignored) { }
    }

    private void warn(String app, String reason, int id) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "Scam warnings", NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("BlackSwan warns you straight away when a message looks like a scam");
            ch.enableVibration(true); ch.setVibrationPattern(new long[] { 0, 400, 150, 400, 150, 400 });
            nm.createNotificationChannel(ch);
        }
        Intent open = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        b.setSmallIcon(getApplicationInfo().icon)
            .setContentTitle("⚠ BlackSwan: possible scam in " + app)
            .setContentText("This message " + reason + ". Don't tap its links or reply.")
            .setStyle(new Notification.BigTextStyle().bigText("This message " + reason + ". Don't tap its links, call its numbers or reply. Open BlackSwan for details."))
            .setColor(0xFFFF2D4A).setAutoCancel(true).setContentIntent(pi);
        if (Build.VERSION.SDK_INT < 26) b.setPriority(Notification.PRIORITY_HIGH).setVibrate(new long[] { 0, 400, 150, 400 });
        try { nm.notify(7000 + Math.abs(id % 1000), b.build()); } catch (SecurityException ignored) { }
    }
}
