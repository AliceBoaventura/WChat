package com.wchat;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class WeChatModActivity extends AppCompatActivity {

    private static final String PREFS = "mod_prefs";
    private static final String KEY_ENABLE = "enable_mock_feature";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_wechat_mod);

        TextView desc = findViewById(R.id.modDesc);
        desc.setText(getString(R.string.wechat_mod_desc));

        TextView result = findViewById(R.id.resultText);
        Switch enableSwitch = findViewById(R.id.enableSwitch);

        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        boolean enabled = prefs.getBoolean(KEY_ENABLE, false);
        enableSwitch.setChecked(enabled);
        result.setText(getString(R.string.mock_result, enabled ? "ON" : "OFF"));

        enableSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean(KEY_ENABLE, isChecked).apply();
                result.setText(getString(R.string.mock_result, isChecked ? "ON" : "OFF"));
            }
        });
    }
}
