package com.wchat;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button goButton = findViewById(R.id.goButton);
        goButton.setOnClickListener(v -> startActivity(new Intent(MainActivity.this, PrototypeActivity.class)));

        Button wechatBtn = findViewById(R.id.openWeChatModButton);
        wechatBtn.setOnClickListener(v -> startActivity(new Intent(MainActivity.this, WeChatModActivity.class)));

        Button predictorBtn = findViewById(R.id.openRedEnvelopePredictorButton);
        predictorBtn.setOnClickListener(v -> startActivity(new Intent(MainActivity.this, RedEnvelopePredictorActivity.class)));
    }
}
