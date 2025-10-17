package com.wchat;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.android.material.textfield.TextInputEditText;

public class PrototypeActivity extends AppCompatActivity {

    private TextInputEditText recipientInput;
    private TextInputEditText messageInput;
    private SwitchMaterial timestampSwitch;
    private TextView previewText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_prototype);

        TextView status = findViewById(R.id.statusText);
        status.setText("Prototype screen ready. Replace with your modified feature here.");
        status.setText(R.string.prototype_ready);

        recipientInput = findViewById(R.id.recipientInput);
        messageInput = findViewById(R.id.messageInput);
        timestampSwitch = findViewById(R.id.timestampSwitch);
        previewText = findViewById(R.id.previewText);
        Button copyButton = findViewById(R.id.copyButton);
        Button shareButton = findViewById(R.id.shareButton);

        TextWatcher watcher = new SimpleTextWatcher(new Runnable() {
            @Override
            public void run() {
                updatePreview();
            }
        });

        recipientInput.addTextChangedListener(watcher);
        messageInput.addTextChangedListener(watcher);
        timestampSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> updatePreview());

        copyButton.setOnClickListener(v -> copyPreviewToClipboard());
        shareButton.setOnClickListener(v -> sharePreview());

        updatePreview();
    }

    private void updatePreview() {
        String recipient = sanitizeInput(recipientInput.getText());
        String message = sanitizeInput(messageInput.getText());

        if (TextUtils.isEmpty(recipient)) {
            recipient = getString(R.string.prototype_default_recipient);
        }
        if (TextUtils.isEmpty(message)) {
            message = getString(R.string.prototype_default_message);
        }

        String preview = PrototypeMessageFormatter.buildMessage(
                recipient,
                message,
                timestampSwitch.isChecked()
        );
        previewText.setText(preview);
    }

    private void copyPreviewToClipboard() {
        CharSequence preview = previewText.getText();
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, R.string.prototype_copy_error, Toast.LENGTH_SHORT).show();
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText("wechat-companion-preview", preview));
        Toast.makeText(this, R.string.prototype_copy_toast, Toast.LENGTH_SHORT).show();
    }

    private void sharePreview() {
        CharSequence preview = previewText.getText();
        Intent sendIntent = new Intent(Intent.ACTION_SEND);
        sendIntent.setType("text/plain");
        sendIntent.putExtra(Intent.EXTRA_TEXT, preview);

        if (sendIntent.resolveActivity(getPackageManager()) == null) {
            Toast.makeText(this, R.string.prototype_share_error, Toast.LENGTH_SHORT).show();
            return;
        }

        Intent chooser = Intent.createChooser(sendIntent, getString(R.string.prototype_share_title));
        startActivity(chooser);
    }

    private String sanitizeInput(CharSequence input) {
        return input == null ? "" : input.toString().trim();
    }

    private static class SimpleTextWatcher implements TextWatcher {

        private final Runnable afterTextChangedCallback;

        SimpleTextWatcher(Runnable afterTextChangedCallback) {
            this.afterTextChangedCallback = afterTextChangedCallback;
        }

        @Override
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            // no-op
        }

        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {
            // no-op
        }

        @Override
        public void afterTextChanged(Editable s) {
            if (afterTextChangedCallback != null) {
                afterTextChangedCallback.run();
            }
        }
    }
}