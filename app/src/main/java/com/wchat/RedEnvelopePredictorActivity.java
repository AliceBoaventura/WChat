package com.wchat;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.security.MessageDigest;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.media.ToneGenerator;
import android.media.AudioManager;

import java.security.NoSuchAlgorithmException;

public class RedEnvelopePredictorActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_red_envelope_predictor);

        final EditText senderInput = findViewById(R.id.senderInput);
        final Button predictBtn = findViewById(R.id.predictBtn);
        final TextView resultText = findViewById(R.id.resultText);
final Animation pop = AnimationUtils.loadAnimation(RedEnvelopePredictorActivity.this, R.anim.dramatic_pop);
final ToneGenerator toneGen = new ToneGenerator(AudioManager.STREAM_MUSIC, 80);

        final TextView noteText = findViewById(R.id.noteText);

        noteText.setText(getString(R.string.red_envelope_note));

        predictBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String sender = senderInput.getText().toString().trim();
                if (sender.isEmpty()) {
                    sender = "anonymous";
                }
                // Deterministic symbolic prediction using SHA-256 hash mapped to a realistic range
                String seed = sender + "_" + System.currentTimeMillis() / (1000*60*60); // hour-granularity seed
                String hash = sha256(seed);
                int valueCents = mapHashToCents(hash);
                // format as currency-like string
                String formatted = String.format("R$ %.2f", valueCents / 100.0);
                resultText.setText(getString(R.string.red_envelope_result, formatted));
// dramatic animation + sound
resultText.startAnimation(pop);
try { toneGen.startTone(android.media.ToneGenerator.TONE_PROP_BEEP, 250); } catch(Exception ex) { /* ignore */ }

            }
        });
    }

    private String sha256(String base) {
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch(Exception ex){
           return Integer.toString(base.hashCode());
        }
    }

    private int mapHashToCents(String hash) {
        // Take first 8 hex chars, convert to int, map to typical red envelope ranges (in cents)
        String sub = hash.substring(0, Math.min(8, hash.length()));
        long val = Long.parseLong(sub, 16);
        // Typical personal envelope: 1.00 to 200.00 BRL (100 to 20000 cents)
        long min = 100;
        long max = 20000;
        long range = max - min + 1;
        int cents = (int)((val % range) + min);
        return cents;
    }
}
