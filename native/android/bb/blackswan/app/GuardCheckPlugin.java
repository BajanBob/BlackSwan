package bb.blackswan.app;

import android.Manifest;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.SystemClock;
import android.provider.Settings;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityNr;
import android.telephony.CellIdentityWcdma;
import android.telephony.CellInfo;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoNr;
import android.telephony.CellInfoWcdma;
import android.telephony.TelephonyManager;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.nfc.NfcAdapter;
import android.net.LinkProperties;
import android.net.ProxyInfo;
import android.net.RouteInfo;
import android.net.wifi.ScanResult;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.Enumeration;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import android.content.SharedPreferences;
import android.content.pm.Signature;
import org.json.JSONArray;

/**
 * BlackSwan (based on GuardYourPhone): reads what Android lets an ordinary app see about the phone's processors, firmware,
 * security settings, installed apps and mobile network. Read-only: it changes nothing by itself.
 */
@CapacitorPlugin(name = "GuardCheck", permissions = {
    @Permission(alias = "phone", strings = { Manifest.permission.READ_PHONE_STATE }),
    @Permission(alias = "location", strings = { Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION })
})
public class GuardCheckPlugin extends Plugin {

    private static String prop(String key) {
        try {
            Process p = Runtime.getRuntime().exec(new String[] { "getprop", key });
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String s = r.readLine();
            r.close();
            return s == null ? "" : s.trim();
        } catch (Exception e) {
            return "";
        }
    }

    private static String nz(String s) { return s == null ? "" : s; }

    static String hex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02X", x)); return sb.toString(); }

    private static String sha256(File f) {
        try (InputStream in = new FileInputStream(f)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536]; int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            return hex(md.digest()).toLowerCase();
        } catch (Exception e) { return ""; }
    }

    // ---------------- BlackSwan: text shared to the app ("Share → BlackSwan") ----------------
    static volatile String sharedText = null;

    /** Returns text another app shared to BlackSwan (a link or a message), once. */
    @PluginMethod
    public void sharedText(PluginCall call) {
        JSObject o = new JSObject();
        String t = sharedText; sharedText = null;
        o.put("text", t == null ? "" : t);
        call.resolve(o);
    }

    // ---------------- BlackSwan: real-time scam guard for notifications ----------------
    /** Whether the person has allowed BlackSwan's scam guard to read notifications. */
    @PluginMethod
    public void scamGuardStatus(PluginCall call) {
        String enabled = nz(Settings.Secure.getString(getContext().getContentResolver(), "enabled_notification_listeners"));
        JSObject o = new JSObject();
        o.put("enabled", enabled.contains(getContext().getPackageName() + "/"));
        call.resolve(o);
    }

    /** Opens the screen where the person can switch the scam guard on or off. */
    @PluginMethod
    public void openScamGuardSettings(PluginCall call) {
        Intent i = new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS");
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try { getContext().startActivity(i); } catch (Exception e) { Intent f = new Intent(Settings.ACTION_SETTINGS); f.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); getContext().startActivity(f); }
        call.resolve();
    }

    /** Saves the daily phishing-domain list for the scam guard, which runs even when BlackSwan is closed. */
    @PluginMethod
    public void setBlocklist(PluginCall call) {
        JSArray d = call.getArray("domains", new JSArray());
        try (FileOutputStream out = new FileOutputStream(new File(getContext().getFilesDir(), BlackSwanNotificationService.BLOCKLIST))) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < d.length(); i++) sb.append(d.getString(i).toLowerCase()).append('\n');
            out.write(sb.toString().getBytes("UTF-8"));
            JSObject o = new JSObject(); o.put("saved", d.length()); call.resolve(o);
        } catch (Exception e) { call.reject("Couldn't save the block list: " + e.getMessage()); }
    }

    /** Scam warnings the guard raised while BlackSwan was closed; returned once, then cleared. */
    @PluginMethod
    public void pendingThreats(PluginCall call) {
        SharedPreferences sp = getContext().getSharedPreferences(BlackSwanNotificationService.PREFS, Context.MODE_PRIVATE);
        String q = sp.getString(BlackSwanNotificationService.QUEUE, "[]");
        sp.edit().putString(BlackSwanNotificationService.QUEUE, "[]").apply();
        JSObject o = new JSObject();
        try { o.put("items", new JSArray(q)); } catch (Exception e) { o.put("items", new JSArray()); }
        call.resolve(o);
    }

    /** Application processor, baseband (modem) firmware, Android build and time since the last restart. */
    @PluginMethod
    public void device(PluginCall call) {
        JSObject o = new JSObject();
        o.put("manufacturer", nz(Build.MANUFACTURER));
        o.put("brand", nz(Build.BRAND));
        o.put("model", nz(Build.MODEL));
        o.put("device", nz(Build.DEVICE));
        o.put("android", nz(Build.VERSION.RELEASE));
        o.put("sdk", Build.VERSION.SDK_INT);
        o.put("securityPatch", nz(Build.VERSION.SECURITY_PATCH));
        o.put("baseband", nz(Build.getRadioVersion()));
        o.put("basebandProp", prop("gsm.version.baseband"));
        o.put("hardware", nz(Build.HARDWARE));
        o.put("board", nz(Build.BOARD));
        o.put("platform", prop("ro.board.platform"));
        o.put("bootloader", nz(Build.BOOTLOADER));
        if (Build.VERSION.SDK_INT >= 31) {
            o.put("socManufacturer", nz(Build.SOC_MANUFACTURER));
            o.put("socModel", nz(Build.SOC_MODEL));
        }
        o.put("abis", String.join(", ", Build.SUPPORTED_ABIS));
        o.put("cores", Runtime.getRuntime().availableProcessors());
        o.put("kernel", nz(System.getProperty("os.version")));
        o.put("fingerprint", nz(Build.FINGERPRINT));
        o.put("buildTags", nz(Build.TAGS));
        o.put("buildType", nz(Build.TYPE));
        o.put("uptimeMs", SystemClock.elapsedRealtime());
        o.put("bootedAt", System.currentTimeMillis() - SystemClock.elapsedRealtime());
        call.resolve(o);
    }

    /** Screen lock, encryption, debugging, verified boot / bootloader, signs of rooting, powerful access. */
    @PluginMethod
    public void security(PluginCall call) {
        Context c = getContext();
        ContentResolver cr = c.getContentResolver();
        JSObject o = new JSObject();
        KeyguardManager km = (KeyguardManager) c.getSystemService(Context.KEYGUARD_SERVICE);
        o.put("screenLock", km != null && km.isDeviceSecure());
        DevicePolicyManager dpm = (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
        int enc = dpm != null ? dpm.getStorageEncryptionStatus() : 0;
        o.put("encrypted", enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER
            || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY);
        o.put("usbDebugging", Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1);
        o.put("developerOptions", Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1);
        o.put("autoTime", Settings.Global.getInt(cr, Settings.Global.AUTO_TIME, 1) == 1);
        o.put("verifiedBoot", prop("ro.boot.verifiedbootstate"));     // green = genuine software
        o.put("flashLocked", prop("ro.boot.flash.locked"));            // 1 = bootloader locked
        o.put("vbmetaState", prop("ro.boot.vbmeta.device_state"));    // locked / unlocked
        o.put("warrantyBit", prop("ro.boot.warranty_bit"));           // Samsung: 1 = Knox tripped
        o.put("testKeys", Build.TAGS != null && Build.TAGS.contains("test-keys"));
        JSArray root = new JSArray();
        for (String p : new String[] { "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/xbin/su", "/data/local/bin/su",
                "/system/app/Superuser.apk", "/system/bin/.ext/su", "/system/usr/we-need-root/su", "/cache/su", "/dev/su" }) {
            if (new File(p).exists()) root.put(p);
        }
        PackageManager pm = c.getPackageManager();
        for (String pkg : new String[] { "com.topjohnwu.magisk", "io.github.huskydg.magisk", "me.weishu.kernelsu", "eu.chainfire.supersu",
                "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser", "com.kingo.root", "com.zachspong.temprootremovejb",
                "de.robv.android.xposed.installer", "org.lsposed.manager" }) {
            try { pm.getPackageInfo(pkg, 0); root.put(pkg); } catch (Exception ignored) { }
        }
        o.put("rootSigns", root);
        o.put("accessibility", nz(Settings.Secure.getString(cr, "enabled_accessibility_services")));
        o.put("notificationListeners", nz(Settings.Secure.getString(cr, "enabled_notification_listeners")));
        o.put("defaultSms", nz(Settings.Secure.getString(cr, "sms_default_application")));
        JSArray admins = new JSArray();
        if (dpm != null && dpm.getActiveAdmins() != null) for (ComponentName a : dpm.getActiveAdmins()) admins.put(a.getPackageName());
        o.put("deviceAdmins", admins);
        o.put("managed", dpm != null && dpm.isDeviceOwnerApp(c.getPackageName()));
        protections(c, cr, o);
        call.resolve(o);
    }

    /** Signs of a man-in-the-middle set-up and the phone's built-in protections (all read-only). */
    private void protections(Context c, ContentResolver cr, JSObject o) {
        // Certificates added by a person or an app let whoever holds them read "secure" (https) traffic.
        JSArray userCas = new JSArray();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            Enumeration<String> al = ks.aliases();
            while (al.hasMoreElements()) {
                String a = al.nextElement();
                if (a.startsWith("user:")) {
                    java.security.cert.Certificate cert = ks.getCertificate(a);
                    String name = a;
                    if (cert instanceof java.security.cert.X509Certificate) name = ((java.security.cert.X509Certificate) cert).getSubjectX500Principal().getName();
                    userCas.put(name);
                }
            }
        } catch (Exception ignored) { }
        o.put("userCaCerts", userCas);
        o.put("httpProxy", nz(Settings.Global.getString(cr, "http_proxy")));
        String sysProxy = System.getProperty("http.proxyHost");
        o.put("systemProxy", sysProxy == null ? "" : sysProxy);
        o.put("privateDnsMode", nz(Settings.Global.getString(cr, "private_dns_mode")));
        o.put("privateDnsHost", nz(Settings.Global.getString(cr, "private_dns_specifier")));
        o.put("bluetoothOn", Settings.Global.getInt(cr, "bluetooth_on", 0) != 0);
        try { NfcAdapter nfc = NfcAdapter.getDefaultAdapter(c); o.put("nfcOn", nfc != null && nfc.isEnabled()); } catch (Exception ignored) { }
        try {
            ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
            boolean vpn = false, wifi = false;
            if (cm != null) for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                if (nc == null) continue;
                if (nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpn = true;
                if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) wifi = true;
            }
            o.put("vpnActive", vpn);
            o.put("onWifi", wifi);
            if (wifi && Build.VERSION.SDK_INT >= 31) {
                WifiManager wm = (WifiManager) c.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                WifiInfo wi = wm != null ? wm.getConnectionInfo() : null;
                if (wi != null) o.put("wifiSecurity", wi.getCurrentSecurityType()); // 0 = open (no password)
            }
        } catch (Exception ignored) { }
        // Android 16 Advanced Protection (Google's strongest setting against spyware and zero-click attacks).
        try {
            Object apm = c.getSystemService("advanced_protection");
            if (apm != null) o.put("advancedProtection", (Boolean) apm.getClass().getMethod("isAdvancedProtectionEnabled").invoke(apm));
        } catch (Throwable ignored) { }
        // Samsung Auto Blocker / Message Guard (setting names differ between One UI versions, so this is best effort).
        for (String k : new String[] { "auto_blocker_enabled", "auto_blocker_setting", "msg_guard_enabled" }) {
            try { String v = Settings.Secure.getString(cr, k); if (v != null) { o.put("samsungAutoBlocker", !"0".equals(v)); break; } } catch (Exception ignored) { }
        }
        o.put("isSamsung", "samsung".equalsIgnoreCase(Build.MANUFACTURER));
    }

    private static final String[] WATCH = {
        Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.SEND_SMS, Manifest.permission.RECORD_AUDIO,
        Manifest.permission.CAMERA, Manifest.permission.ACCESS_FINE_LOCATION, "android.permission.ACCESS_BACKGROUND_LOCATION",
        Manifest.permission.READ_CONTACTS, Manifest.permission.READ_CALL_LOG, Manifest.permission.READ_PHONE_STATE, Manifest.permission.CALL_PHONE,
        Manifest.permission.BODY_SENSORS, Manifest.permission.READ_EXTERNAL_STORAGE, "android.permission.READ_MEDIA_IMAGES",
        Manifest.permission.SYSTEM_ALERT_WINDOW, Manifest.permission.REQUEST_INSTALL_PACKAGES, "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.QUERY_ALL_PACKAGES", "android.permission.PACKAGE_USAGE_STATS", "android.permission.BIND_DEVICE_ADMIN"
    };

    /** Installed apps: where each came from, and the powerful permissions it holds. */
    @PluginMethod
    public void apps(PluginCall call) {
        final Context c = getContext();
        new Thread(() -> {
            try {
                PackageManager pm = c.getPackageManager();
                ContentResolver cr = c.getContentResolver();
                String acc = nz(Settings.Secure.getString(cr, "enabled_accessibility_services"));
                String lis = nz(Settings.Secure.getString(cr, "enabled_notification_listeners"));
                Set<String> admins = new HashSet<>();
                DevicePolicyManager dpm = (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
                if (dpm != null && dpm.getActiveAdmins() != null) for (ComponentName a : dpm.getActiveAdmins()) admins.add(a.getPackageName());
                Set<String> watch = new HashSet<>(Arrays.asList(WATCH));
                int flags = PackageManager.GET_PERMISSIONS | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
                List<PackageInfo> list = pm.getInstalledPackages(flags);
                JSArray out = new JSArray();
                int system = 0;
                for (PackageInfo p : list) {
                    ApplicationInfo ai = p.applicationInfo;
                    if (ai == null) continue;
                    boolean isSystem = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0 && (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
                    boolean special = acc.contains(p.packageName + "/") || lis.contains(p.packageName + "/") || admins.contains(p.packageName);
                    if (isSystem && !special) { system++; continue; }
                    JSObject a = new JSObject();
                    a.put("package", p.packageName);
                    a.put("name", String.valueOf(pm.getApplicationLabel(ai)));
                    a.put("version", nz(p.versionName));
                    a.put("system", isSystem);
                    a.put("installed", p.firstInstallTime);
                    a.put("updated", p.lastUpdateTime);
                    String installer = null;
                    try {
                        if (Build.VERSION.SDK_INT >= 30) installer = pm.getInstallSourceInfo(p.packageName).getInstallingPackageName();
                        else installer = pm.getInstallerPackageName(p.packageName);
                    } catch (Exception ignored) { }
                    a.put("installer", installer == null ? "" : installer);
                    a.put("accessibility", acc.contains(p.packageName + "/"));
                    a.put("notificationListener", lis.contains(p.packageName + "/"));
                    a.put("deviceAdmin", admins.contains(p.packageName));
                    a.put("enabled", ai.enabled);
                    JSArray perms = new JSArray();
                    if (p.requestedPermissions != null) {
                        for (int i = 0; i < p.requestedPermissions.length; i++) {
                            String perm = p.requestedPermissions[i];
                            if (!watch.contains(perm)) continue;
                            boolean granted = p.requestedPermissionsFlags != null && (p.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
                            if (granted || perm.equals(Manifest.permission.SYSTEM_ALERT_WINDOW) || perm.equals(Manifest.permission.REQUEST_INSTALL_PACKAGES)
                                || perm.equals("android.permission.MANAGE_EXTERNAL_STORAGE") || perm.equals("android.permission.QUERY_ALL_PACKAGES")
                                || perm.equals("android.permission.PACKAGE_USAGE_STATS")) {
                                perms.put(perm.substring(perm.lastIndexOf('.') + 1));
                            }
                        }
                    }
                    a.put("permissions", perms);
                    // BlackSwan: signing-certificate fingerprints (to match known spy apps even when renamed),
                    // and a SHA-256 of apps installed from a file (to match known malware).
                    JSArray certs = new JSArray();
                    try {
                        Signature[] sigs = null;
                        if (Build.VERSION.SDK_INT >= 28 && p.signingInfo != null) sigs = p.signingInfo.hasMultipleSigners() ? p.signingInfo.getApkContentsSigners() : p.signingInfo.getSigningCertificateHistory();
                        else sigs = p.signatures;
                        if (sigs != null) for (Signature sg : sigs) certs.put(hex(MessageDigest.getInstance("SHA-1").digest(sg.toByteArray())));
                    } catch (Exception ignored) { }
                    a.put("certs", certs);
                    boolean fromFile = !isSystem && (installer == null || installer.isEmpty() || installer.contains("packageinstaller"));
                    if (fromFile && ai.sourceDir != null) {
                        File apk = new File(ai.sourceDir);
                        if (apk.length() < 300L * 1024 * 1024) a.put("sha256", sha256(apk));
                    }
                    out.put(a);
                }
                JSObject o = new JSObject();
                o.put("apps", out);
                o.put("systemApps", system);
                o.put("total", list.size());
                call.resolve(o);
            } catch (Exception e) {
                call.reject("Couldn't read the app list: " + e.getMessage());
            }
        }).start();
    }

    /** Mobile network: operator, 2G/3G/4G/5G and the cell towers the phone can see (needs phone + location permission). */
    @PluginMethod
    public void network(PluginCall call) {
        if (getPermissionState("phone") != PermissionState.GRANTED || getPermissionState("location") != PermissionState.GRANTED) {
            requestPermissionForAliases(new String[] { "phone", "location" }, call, "networkPermsDone");
            return;
        }
        readNetwork(call);
    }

    @PermissionCallback
    private void networkPermsDone(PluginCall call) { readNetwork(call); }

    private static String gen(int t) {
        switch (t) {
            case TelephonyManager.NETWORK_TYPE_GPRS: case TelephonyManager.NETWORK_TYPE_EDGE: case TelephonyManager.NETWORK_TYPE_CDMA:
            case TelephonyManager.NETWORK_TYPE_1xRTT: case TelephonyManager.NETWORK_TYPE_IDEN: case TelephonyManager.NETWORK_TYPE_GSM:
                return "2G";
            case TelephonyManager.NETWORK_TYPE_UMTS: case TelephonyManager.NETWORK_TYPE_EVDO_0: case TelephonyManager.NETWORK_TYPE_EVDO_A:
            case TelephonyManager.NETWORK_TYPE_HSDPA: case TelephonyManager.NETWORK_TYPE_HSUPA: case TelephonyManager.NETWORK_TYPE_HSPA:
            case TelephonyManager.NETWORK_TYPE_EVDO_B: case TelephonyManager.NETWORK_TYPE_EHRPD: case TelephonyManager.NETWORK_TYPE_HSPAP:
            case TelephonyManager.NETWORK_TYPE_TD_SCDMA:
                return "3G";
            case TelephonyManager.NETWORK_TYPE_LTE: case TelephonyManager.NETWORK_TYPE_IWLAN:
                return "4G";
            case TelephonyManager.NETWORK_TYPE_NR:
                return "5G";
            default:
                return "";
        }
    }

    private void readNetwork(PluginCall call) {
        Context c = getContext();
        TelephonyManager tm = (TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE);
        JSObject o = new JSObject();
        o.put("phonePermission", getPermissionState("phone") == PermissionState.GRANTED);
        o.put("locationPermission", getPermissionState("location") == PermissionState.GRANTED);
        if (tm == null) { o.put("noTelephony", true); call.resolve(o); return; }
        o.put("operator", nz(tm.getNetworkOperatorName()));
        o.put("simOperator", nz(tm.getSimOperatorName()));
        o.put("country", nz(tm.getNetworkCountryIso()));
        o.put("roaming", tm.isNetworkRoaming());
        o.put("simState", tm.getSimState());
        try { o.put("data", gen(tm.getDataNetworkType())); } catch (SecurityException ignored) { }
        try { o.put("voice", gen(tm.getVoiceNetworkType())); } catch (SecurityException ignored) { }
        JSArray cells = new JSArray();
        try {
            List<CellInfo> list = tm.getAllCellInfo();
            if (list != null) for (CellInfo ci : list) {
                JSObject x = new JSObject();
                x.put("registered", ci.isRegistered());
                if (ci instanceof CellInfoGsm) {
                    CellIdentityGsm id = ((CellInfoGsm) ci).getCellIdentity();
                    x.put("gen", "2G"); x.put("cell", id.getCid()); x.put("area", id.getLac()); x.put("dbm", ((CellInfoGsm) ci).getCellSignalStrength().getDbm());
                } else if (ci instanceof CellInfoWcdma) {
                    CellIdentityWcdma id = ((CellInfoWcdma) ci).getCellIdentity();
                    x.put("gen", "3G"); x.put("cell", id.getCid()); x.put("area", id.getLac()); x.put("dbm", ((CellInfoWcdma) ci).getCellSignalStrength().getDbm());
                } else if (ci instanceof CellInfoLte) {
                    CellIdentityLte id = ((CellInfoLte) ci).getCellIdentity();
                    x.put("gen", "4G"); x.put("cell", id.getCi()); x.put("area", id.getTac()); x.put("dbm", ((CellInfoLte) ci).getCellSignalStrength().getDbm());
                } else if (Build.VERSION.SDK_INT >= 29 && ci instanceof CellInfoNr) {
                    CellIdentityNr id = (CellIdentityNr) ((CellInfoNr) ci).getCellIdentity();
                    x.put("gen", "5G"); x.put("cell", id.getNci()); x.put("area", id.getTac()); x.put("dbm", ((CellInfoNr) ci).getCellSignalStrength().getDbm());
                } else {
                    x.put("gen", "other");
                }
                cells.put(x);
            }
        } catch (SecurityException ignored) { }
        o.put("cells", cells);
        call.resolve(o);
    }

    /**
     * BlackSwan intrusion monitor: the current Wi-Fi / link details (access point, router, DNS, proxy, captive portal)
     * and nearby access points with the same name, for evil-twin and man-in-the-middle checks. Needs location permission
     * because Android hides Wi-Fi names and access points from apps without it. Read-only.
     */
    @PluginMethod
    public void wifi(PluginCall call) {
        if (getPermissionState("location") != PermissionState.GRANTED) {
            requestPermissionForAlias("location", call, "wifiPermsDone");
            return;
        }
        readWifi(call);
    }

    @PermissionCallback
    private void wifiPermsDone(PluginCall call) { readWifi(call); }

    private void readWifi(PluginCall call) {
        Context c = getContext();
        JSObject o = new JSObject();
        o.put("locationPermission", getPermissionState("location") == PermissionState.GRANTED);
        try {
            ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network n = cm != null ? cm.getActiveNetwork() : null;
            NetworkCapabilities nc = n != null ? cm.getNetworkCapabilities(n) : null;
            o.put("onWifi", nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI));
            o.put("vpn", nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
            o.put("validated", nc != null && nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
            o.put("captivePortal", nc != null && nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL));
            LinkProperties lp = n != null ? cm.getLinkProperties(n) : null;
            if (lp != null) {
                JSArray dns = new JSArray();
                for (InetAddress a : lp.getDnsServers()) dns.put(a.getHostAddress());
                o.put("dns", dns);
                String gw = "";
                for (RouteInfo r : lp.getRoutes()) {
                    if (r.isDefaultRoute() && r.getGateway() != null && !r.getGateway().isAnyLocalAddress()) { gw = r.getGateway().getHostAddress(); break; }
                }
                o.put("gateway", gw);
                if (Build.VERSION.SDK_INT >= 28) {
                    o.put("privateDnsActive", lp.isPrivateDnsActive());
                    o.put("privateDnsServer", nz(lp.getPrivateDnsServerName()));
                }
                ProxyInfo pi = lp.getHttpProxy();
                o.put("proxy", pi == null || pi.getHost() == null ? "" : pi.getHost() + ":" + pi.getPort());
                o.put("iface", nz(lp.getInterfaceName()));
            }
            WifiManager wm = (WifiManager) c.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            WifiInfo wi = wm != null ? wm.getConnectionInfo() : null;
            String ssid = "";
            if (wi != null) {
                ssid = nz(wi.getSSID()).replace("\"", "");
                o.put("ssid", ssid);
                o.put("bssid", nz(wi.getBSSID()));
                o.put("rssi", wi.getRssi());
                o.put("frequency", wi.getFrequency());
                o.put("linkSpeed", wi.getLinkSpeed());
                if (Build.VERSION.SDK_INT >= 31) o.put("security", wi.getCurrentSecurityType());
            }
            JSArray twins = new JSArray();
            if (wm != null && !ssid.isEmpty() && !"<unknown ssid>".equals(ssid)) {
                try {
                    for (ScanResult sr : wm.getScanResults()) {
                        if (!ssid.equals(sr.SSID)) continue;
                        JSObject t = new JSObject();
                        t.put("bssid", nz(sr.BSSID));
                        t.put("level", sr.level);
                        t.put("frequency", sr.frequency);
                        t.put("caps", nz(sr.capabilities));
                        twins.put(t);
                    }
                } catch (SecurityException ignored) { }
            }
            o.put("sameName", twins);
        } catch (Exception e) {
            o.put("error", String.valueOf(e.getMessage()));
        }
        call.resolve(o);
    }

    /** Opens the right Settings screen so the person can fix something themselves. */
    @PluginMethod
    public void openSettings(PluginCall call) {
        String to = call.getString("to", "");
        String pkg = call.getString("package", "");
        String action;
        switch (to) {
            case "security": action = Settings.ACTION_SECURITY_SETTINGS; break;
            case "developer": action = Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS; break;
            case "accessibility": action = Settings.ACTION_ACCESSIBILITY_SETTINGS; break;
            case "notificationAccess": action = "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"; break;
            case "network": action = "android.settings.NETWORK_OPERATOR_SETTINGS"; break;
            case "update": action = "android.settings.SYSTEM_UPDATE_SETTINGS"; break;
            case "app": action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS; break;
            case "notifications": action = Settings.ACTION_APP_NOTIFICATION_SETTINGS; break;
            default: action = Settings.ACTION_SETTINGS;
        }
        Intent i = new Intent(action);
        if ("app".equals(to)) i.setData(Uri.parse("package:" + pkg));
        if ("notifications".equals(to)) i.putExtra(Settings.EXTRA_APP_PACKAGE, getContext().getPackageName());
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try { getContext().startActivity(i); }
        catch (Exception e) {
            Intent f = new Intent(Settings.ACTION_SETTINGS); f.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try { getContext().startActivity(f); } catch (Exception ignored) { }
        }
        call.resolve();
    }

    /** Asks Android to uninstall an app (Android shows its own confirmation). */
    @PluginMethod
    public void uninstall(PluginCall call) {
        String pkg = call.getString("package", "");
        if (pkg.isEmpty()) { call.reject("No app given"); return; }
        Intent i = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + pkg));
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try { getContext().startActivity(i); call.resolve(); } catch (Exception e) { call.reject("Couldn't open the uninstall screen"); }
    }
}
