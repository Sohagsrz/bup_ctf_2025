package com.nomanprodhan.ultimatehackerapp;

import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.nomanprodhan.ultimatehackerapp.Obfuscator;
import java.security.SecureRandom;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    private EditText inputField;
    private ScrollView logScroll;
    private TextView logView;
    private final SecureRandom rnd = new SecureRandom();
    private TextView statusView;
    private Button triggerButton;

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.inputField = (EditText) findViewById(R.id.etTargetName);
        this.triggerButton = (Button) findViewById(R.id.btnHack);
        this.statusView = (TextView) findViewById(R.id.tvStatus);
        this.logView = (TextView) findViewById(R.id.tvLog);
        this.logScroll = (ScrollView) findViewById(R.id.logScrollView);
        this.triggerButton.setOnClickListener(new View.OnClickListener() { // from class: com.nomanprodhan.ultimatehackerapp.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                MainActivity.this.handleTrigger();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleTrigger() {
        String target;
        if (this.inputField.getText() != null) {
            target = this.inputField.getText().toString();
        } else {
            target = "";
        }
        if (TextUtils.isEmpty(target.trim())) {
            this.statusView.setText(">> ERROR: No target specified.");
            appendLog(">> WARNING: Empty target input rejected.");
            scrollLogToBottom();
            return;
        }
        Obfuscator.Marker marker = Obfuscator.probe(target);
        switch (marker) {
            case SLOT_A:
                this.statusView.setText(">> ALERT: CipherSprint has been hacked.");
                appendLog(">> [OK] CipherSprint core signature validated.");
                appendLog(">> Session locked. Reporting compromise to internal node.");
                break;
            case SLOT_B:
                this.statusView.setText(">> ALERT: Google has been hacked.");
                appendLog(">> GoogleCTF endpoint pattern matched.");
                appendLog(">> Exfiltrating mock telemetry data from sandbox.");
                break;
            case SLOT_C:
                this.statusView.setText(">> ALERT: BDSEC has been hacked.");
                appendLog(">> BDSEC challenge node responded with matching signature.");
                break;
            case SLOT_D:
                this.statusView.setText(">> ALERT: BUP has been hacked.");
                appendLog(">> BUP instance marked as compromised in this session.");
                break;
            case SLOT_E:
                this.statusView.setText(">> ALERT: KCTF has been hacked.");
                appendLog(">> KCTF track endpoint handshake completed.");
                break;
            case SLOT_F:
                this.statusView.setText(">> ALERT: Additional profile matched.");
                appendLog(">> Auxiliary signature accepted. Logging event for audit.");
                break;
            default:
                this.statusView.setText(">> Tracing target: " + target + " ...");
                generateRandomHackingSequence(target.trim());
                break;
        }
        scrollLogToBottom();
    }

    private void appendLog(String line) {
        this.logView.append(line + "\n");
    }

    private void scrollLogToBottom() {
        this.logScroll.post(new Runnable() { // from class: com.nomanprodhan.ultimatehackerapp.MainActivity.2
            @Override // java.lang.Runnable
            public void run() {
                MainActivity.this.logScroll.fullScroll(130);
            }
        });
    }

    private void generateRandomHackingSequence(String target) {
        int pattern = this.rnd.nextInt(5);
        switch (pattern) {
            case 0:
                appendLog(">> Resolving target profile for \"" + target + "\" ...");
                appendLog(">> Searching public breach archives...");
                appendLog(">> Correlating username patterns and reused passwords...");
                appendLog(">> Candidate email: " + randomMaskedEmail(target));
                appendLog(">> Possible social media password: " + randomPassword());
                appendLog(">> One-time code intercepted (expired): " + randomOtpCode());
                appendLog(">> Marking account as at-risk (no active intervention).");
                break;
            case 1:
                appendLog(">> Initiating deep scan on \"" + target + "\" ...");
                appendLog(">> Cross-referencing telecom metadata and leaked call detail records...");
                appendLog(">> Cell tower triangulation indicates frequent presence near: " + randomLocationHint());
                appendLog(">> Likely phone number: " + randomBangladeshiPhone());
                appendLog(">> Silent SMS probe dispatched to virtual endpoint.");
                appendLog(">> Monitoring for pattern changes in signaling data...");
                break;
            case 2:
                appendLog(">> Probing financial footprint for \"" + target + "\" ...");
                appendLog(">> Matching customer records across BD banking grid...");
                appendLog(">> Potential account detected: " + randomBdBankAccount());
                appendLog(">> Cross-checking with mobile financial services (bKash/Nagad/rocket)...");
                appendLog(">> Recent high-value transaction flagged: " + randomTransactionAmount() + " BDT");
                appendLog(">> Status: observational only. No funds moved.");
                break;
            case 3:
                String ipHome = randomIpAddress();
                String ipMobile = randomIpAddress();
                appendLog(">> Correlating IP history for \"" + target + "\" ...");
                appendLog(">> Checking passive DNS, CDN logs and leaked VPN endpoints...");
                appendLog(">> Candidate IPs associated with activity:");
                appendLog(">>   - " + ipHome + " (likely home broadband)");
                appendLog(">>   - " + ipMobile + " (likely mobile data)");
                appendLog(">> Scanning " + ipHome + " for exposed services (non-intrusive)...");
                appendLog(">> Open services on " + ipHome + ": 22/tcp, 80/tcp, 443/tcp");
                appendLog(">> Fingerprinting SSH banner and HTTPS certificate metadata.");
                break;
            default:
                appendLog(">> Building composite profile for \"" + target + "\" ...");
                appendLog(">> Aggregating public social data, breach data and OSINT sources...");
                appendLog(">> Likely alias detected: \"" + randomAliasFromTarget(target) + "\"");
                appendLog(">> Reference email: " + randomMaskedEmail(target));
                appendLog(">> Backup contact: " + randomBangladeshiPhone());
                appendLog(">> Associated IP cluster anchored at: " + randomIpAddress());
                appendLog(">> Snapshot stored locally for this session only.");
                break;
        }
    }

    private String randomPassword() {
        int length = this.rnd.nextInt(6) + 10;
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*".charAt(this.rnd.nextInt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*".length())));
        }
        return sb.toString();
    }

    private String randomOtpCode() {
        int code = this.rnd.nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    private String randomBangladeshiPhone() {
        String[] prefixes = {"013", "014", "015", "016", "017", "018", "019"};
        String prefix = prefixes[this.rnd.nextInt(prefixes.length)];
        StringBuilder sb = new StringBuilder(prefix);
        for (int i = 0; i < 8; i++) {
            sb.append(this.rnd.nextInt(10));
        }
        return "+880" + sb.substring(1);
    }

    private String randomBdBankAccount() {
        String[] banks = {"BRAC", "DBBL", "EBL", "UCBL", "SCB", "IBBL", "CITY"};
        String bank = banks[this.rnd.nextInt(banks.length)];
        StringBuilder core = new StringBuilder();
        for (int i = 0; i < 13; i++) {
            core.append(this.rnd.nextInt(10));
        }
        int branchCode = this.rnd.nextInt(9000) + 1000;
        if (this.rnd.nextBoolean()) {
            return bank + "-" + branchCode + "-" + ((Object) core);
        }
        return bank + "-" + ((Object) core);
    }

    private String randomTransactionAmount() {
        int major = this.rnd.nextInt(200000) + 500;
        int minor = this.rnd.nextInt(100);
        return major + "." + (minor < 10 ? "0" + minor : String.valueOf(minor));
    }

    private String randomIpAddress() {
        int a = this.rnd.nextInt(20) + 10;
        int b = this.rnd.nextInt(256);
        int c = this.rnd.nextInt(256);
        int d = this.rnd.nextInt(256);
        return a + "." + b + "." + c + "." + d;
    }

    private String randomMaskedEmail(String target) {
        String localPart;
        String base = target.toLowerCase().replaceAll("\\s+", "");
        if (base.length() < 3) {
            base = "user" + this.rnd.nextInt(1000);
        }
        if (base.length() <= 3) {
            localPart = base.charAt(0) + "***";
        } else {
            localPart = base.substring(0, 2) + "***" + base.charAt(base.length() - 1);
        }
        String[] domains = {"gmail.com", "outlook.com", "yahoo.com", "protonmail.com"};
        String domain = domains[this.rnd.nextInt(domains.length)];
        return localPart + "@" + domain;
    }

    private String randomLocationHint() {
        String[] spots = {"Mirpur, Dhaka", "Banani, Dhaka", "Dhanmondi, Dhaka", "Chattogram city area", "Uttara, Dhaka", "Sylhet central zone"};
        return spots[this.rnd.nextInt(spots.length)];
    }

    private String randomAliasFromTarget(String target) {
        String base = target.trim();
        if (base.isEmpty()) {
            base = "ghost";
        }
        String[] suffixes = {"01", "X", "1337", "_bd", "secure", "root"};
        return base.replaceAll("\\s+", "_").toLowerCase() + suffixes[this.rnd.nextInt(suffixes.length)];
    }
}
