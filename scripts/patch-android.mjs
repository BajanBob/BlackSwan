// Runs after `cap add android`: adds BlackSwan's native check plugin, its permissions and the version.
import fs from 'node:fs';
import path from 'node:path';
const pkgDir = 'android/app/src/main/java/bb/blackswan/app';
fs.mkdirSync(pkgDir, { recursive: true });
for (const f of ['GuardCheckPlugin.java', 'BlackSwanNotificationService.java']) fs.copyFileSync(`native/android/bb/blackswan/app/${f}`, path.join(pkgDir, f));
fs.writeFileSync(path.join(pkgDir, 'MainActivity.java'), `package bb.blackswan.app;

import android.content.Intent;
import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(GuardCheckPlugin.class);
        super.onCreate(savedInstanceState);
        takeShared(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        takeShared(intent);
    }

    /** "Share → BlackSwan" from any app: keep the shared link or message for the app to scan. */
    private void takeShared(Intent i) {
        if (i != null && Intent.ACTION_SEND.equals(i.getAction()) && "text/plain".equals(i.getType())) {
            String t = i.getStringExtra(Intent.EXTRA_TEXT);
            if (t != null) GuardCheckPlugin.sharedText = t;
        }
    }
}
`);
const p = 'android/app/src/main/AndroidManifest.xml';
let m = fs.readFileSync(p, 'utf8');
// QUERY_ALL_PACKAGES: to list every installed app (BlackSwan is a security tool distributed directly, not on Google Play).
for (const perm of ['INTERNET', 'READ_PHONE_STATE', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'QUERY_ALL_PACKAGES', 'REQUEST_DELETE_PACKAGES', 'POST_NOTIFICATIONS', 'RECEIVE_BOOT_COMPLETED', 'ACCESS_WIFI_STATE', 'ACCESS_NETWORK_STATE', 'QUERY_ADVANCED_PROTECTION_MODE', 'USE_BIOMETRIC', 'CHANGE_WIFI_STATE']) {
  if (!m.includes(`android.permission.${perm}"`)) m = m.replace('</manifest>', `    <uses-permission android:name="android.permission.${perm}" />\n</manifest>`);
}
m = m.replace('</manifest>', '    <uses-feature android:name="android.hardware.telephony" android:required="false" />\n    <uses-feature android:name="android.hardware.location" android:required="false" />\n</manifest>');
m = m.replace(/android:allowBackup="true"/, 'android:allowBackup="false"');
// BlackSwan: "Share → BlackSwan" for links and messages, and the real-time scam guard (notification access, opt-in).
if (!m.includes('android.intent.action.SEND')) {
  const actEnd = m.indexOf('</activity>');
  m = m.slice(0, actEnd) + `    <intent-filter android:label="Check with BlackSwan">
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="text/plain" />
            </intent-filter>
        ` + m.slice(actEnd);
}
if (!m.includes('BlackSwanNotificationService')) {
  m = m.replace('</application>', `    <service android:name=".BlackSwanNotificationService" android:label="BlackSwan scam guard" android:exported="true"
            android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
            <intent-filter><action android:name="android.service.notification.NotificationListenerService" /></intent-filter>
        </service>
    </application>`);
}
if (!/android:launchMode=/.test(m)) m = m.replace(/(<activity[^>]*android:name="\.MainActivity")/, '$1 android:launchMode="singleTask"');
if (!m.includes('usesCleartextTraffic')) m = m.replace('<application', '<application android:usesCleartextTraffic="false"');
fs.writeFileSync(p, m);
const vars = 'android/variables.gradle';
if (fs.existsSync(vars)) {
  let v = fs.readFileSync(vars, 'utf8');
  v = v.replace(/(compileSdkVersion|targetSdkVersion)\s*=\s*(\d+)/g, (all, k, n) => `${k} = ${Math.max(Number(n), 36)}`);
  fs.writeFileSync(vars, v);
}
const { version } = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const [a, b, c] = version.split('.').map(Number);
const code = a * 10000 + b * 100 + c;
const gradle = 'android/app/build.gradle';
let g = fs.readFileSync(gradle, 'utf8');
g = g.replace(/versionCode\s+\d+/, `versionCode ${code}`).replace(/versionName\s+"[^"]*"/, `versionName "${version}"`);
fs.writeFileSync(gradle, g);
console.log(`Android project patched for BlackSwan (version ${version}, code ${code})`);
