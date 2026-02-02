package de.niklasmerz.cordova.biometric;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.util.concurrent.Executor;
import java.util.regex.Pattern;

import javax.crypto.Cipher;

public class BiometricActivity extends AppCompatActivity {

    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 2;
    private PromptInfo mPromptInfo;
    private CryptographyManager mCryptographyManager;
    private static final String SECRET_KEY = "__aio_secret_key";
    private BiometricPrompt mBiometricPrompt;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(null);
        int layout = getResources()
                .getIdentifier("biometric_activity", "layout", getPackageName());
        setContentView(layout);

        if (savedInstanceState != null) {
            return;
        }

        mCryptographyManager = new CryptographyManagerImpl();
        mPromptInfo = new PromptInfo.Builder(getIntent().getExtras()).build();
        final Handler handler = new Handler(Looper.getMainLooper());
        Executor executor = handler::post;
        mBiometricPrompt = new BiometricPrompt(this, executor, mAuthenticationCallback);
        try {
            authenticate();
        } catch (CryptoException e) {
            finishWithError(e);
        } catch (Exception e) {
            finishWithError(PluginError.BIOMETRIC_UNKNOWN_ERROR, e.getMessage());
        }
    }

    private void authenticate() throws CryptoException {
        switch (mPromptInfo.getType()) {
          case JUST_AUTHENTICATE:
            justAuthenticate();
            return;
          case REGISTER_SECRET:
            authenticateToEncrypt(mPromptInfo.invalidateOnEnrollment());
            return;
          case LOAD_SECRET:
            authenticateToDecrypt();
            return;
          case MIGRATE_SECRET:
            authenticateToMigrate();
            return;
        }
        throw new CryptoException(PluginError.BIOMETRIC_ARGS_PARSING_FAILED);
    }

    private void authenticateToEncrypt(boolean invalidateOnEnrollment) throws CryptoException {
        if (mPromptInfo.getSecret() == null) {
            throw new CryptoException(PluginError.BIOMETRIC_ARGS_PARSING_FAILED);
        }
        Cipher cipher = mCryptographyManager
                .getInitializedCipherForEncryption(SECRET_KEY, invalidateOnEnrollment, this);
        mBiometricPrompt.authenticate(createPromptInfo(), new BiometricPrompt.CryptoObject(cipher));
    }

    private void justAuthenticate() {
        mBiometricPrompt.authenticate(createPromptInfo());
    }

    private void authenticateToDecrypt() throws CryptoException {
        String token = this.mPromptInfo.getToken();
        boolean useLegacyCipher = token != null;

        String clientId = this.mPromptInfo.getClientId();
        String username = this.mPromptInfo.getUsername();
        byte[] initializationVector = EncryptedData.loadInitializationVector(this, useLegacyCipher, clientId, username);

        Cipher cipher;
        if (useLegacyCipher) {
            cipher = mCryptographyManager.getInitializedCipherForDecryptionLegacy(clientId, initializationVector, this);
        } else {
            cipher = mCryptographyManager.getInitializedCipherForDecryption(SECRET_KEY, initializationVector, this);
        }

        mBiometricPrompt.authenticate(createPromptInfo(), new BiometricPrompt.CryptoObject(cipher));
    }

    private void authenticateToMigrate() throws CryptoException {
        String token = this.mPromptInfo.getToken();
        String clientId = this.mPromptInfo.getClientId();
        String username = this.mPromptInfo.getUsername();

        if (token == null || clientId == null || username == null) {
            throw new CryptoException(PluginError.BIOMETRIC_ARGS_PARSING_FAILED);
        }

        byte[] initializationVector = EncryptedData.loadInitializationVector(this, true, clientId, username);
        Cipher cipher = mCryptographyManager.getInitializedCipherForDecryptionLegacy(clientId, initializationVector, this);

        mBiometricPrompt.authenticate(createPromptInfo(), new BiometricPrompt.CryptoObject(cipher));
    }

    private BiometricPrompt.PromptInfo createPromptInfo() {
        BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(mPromptInfo.getTitle())
                .setSubtitle(mPromptInfo.getSubtitle())
                .setConfirmationRequired(mPromptInfo.getConfirmationRequired())
                .setDescription(mPromptInfo.getDescription());

        if (mPromptInfo.isDeviceCredentialAllowed()
                && mPromptInfo.getType() == BiometricActivityType.JUST_AUTHENTICATE
                && Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) { // TODO: remove after fix https://issuetracker.google.com/issues/142740104
            promptInfoBuilder.setDeviceCredentialAllowed(true);
        } else {
            promptInfoBuilder.setNegativeButtonText(mPromptInfo.getCancelButtonTitle());
        }
        return promptInfoBuilder.build();
    }

    private BiometricPrompt.AuthenticationCallback mAuthenticationCallback =
            new BiometricPrompt.AuthenticationCallback() {

                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    onError(errorCode, errString);
                }

                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    try {
                        finishWithSuccess(result.getCryptoObject());
                    } catch (CryptoException e) {
                        finishWithError(e);
                    }
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    //onError(PluginError.BIOMETRIC_AUTHENTICATION_FAILED.getValue(), PluginError.BIOMETRIC_AUTHENTICATION_FAILED.getMessage());
                }
            };


    // TODO: remove after fix https://issuetracker.google.com/issues/142740104
    private void showAuthenticationScreen() {
        KeyguardManager keyguardManager = ContextCompat
                .getSystemService(this, KeyguardManager.class);
        if (keyguardManager == null
                || android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        if (keyguardManager.isKeyguardSecure()) {
            Intent intent = keyguardManager
                    .createConfirmDeviceCredentialIntent(mPromptInfo.getTitle(), mPromptInfo.getDescription());
            this.startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        } else {
            // Show a message that the user hasn't set up a lock screen.
            finishWithError(PluginError.BIOMETRIC_SCREEN_GUARD_UNSECURED);
        }
    }

    // TODO: remove after fix https://issuetracker.google.com/issues/142740104
    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            if (resultCode == Activity.RESULT_OK) {
                finishWithSuccess();
            } else {
                finishWithError(PluginError.BIOMETRIC_PIN_OR_PATTERN_DISMISSED);
            }
        }
    }

    private void onError(int errorCode, @NonNull CharSequence errString) {

        switch (errorCode)
        {
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_CANCELED:
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                return;
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                // TODO: remove after fix https://issuetracker.google.com/issues/142740104
                if (Build.VERSION.SDK_INT > Build.VERSION_CODES.P && mPromptInfo.isDeviceCredentialAllowed()) {
                    showAuthenticationScreen();
                    return;
                }
                finishWithError(PluginError.BIOMETRIC_DISMISSED);
                break;
            case BiometricPrompt.ERROR_LOCKOUT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT.getValue(), errString.toString());
                break;
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                finishWithError(PluginError.BIOMETRIC_LOCKED_OUT_PERMANENT.getValue(), errString.toString());
                break;
            default:
                finishWithError(errorCode, errString.toString());
        }
    }

    private void finishWithSuccess() {
        setResult(RESULT_OK);
        finish();
    }

    private void finishWithSuccess(BiometricPrompt.CryptoObject cryptoObject) throws CryptoException {
        Intent intent = null;
        switch (mPromptInfo.getType()) {
          case REGISTER_SECRET:
            encrypt(cryptoObject);
            break;
          case LOAD_SECRET:
            intent = getDecryptedIntent(cryptoObject);
            break;
          case MIGRATE_SECRET:
            intent = migrateSecret(cryptoObject);
            break;
        }
        if (intent == null) {
            setResult(RESULT_OK);
        } else {
            setResult(RESULT_OK, intent);
        }
        finish();
    }

    private void encrypt(BiometricPrompt.CryptoObject cryptoObject) throws CryptoException {
        String text = mPromptInfo.getSecret();
        EncryptedData encryptedData = mCryptographyManager.encryptData(text, cryptoObject.getCipher());
        encryptedData.save(this);
    }

    private Intent migrateSecret(BiometricPrompt.CryptoObject cryptoObject) throws CryptoException {
        // Step 1: Decrypt the legacy token
        String token = this.mPromptInfo.getToken();
        byte[] ciphertext = Base64.decode(token, Base64.NO_WRAP);

        String decryptedSecret = mCryptographyManager.decryptData(ciphertext, cryptoObject.getCipher());
        if (decryptedSecret == null) {
            throw new CryptoException(PluginError.BIOMETRIC_NO_SECRET_FOUND);
        }

        // Step 2: Extract password from legacy format ("clientId|:|password" or "clientId:password")
        String password = getPassword(decryptedSecret);
        if (password == null) {
            throw new CryptoException(PluginError.BIOMETRIC_ARGS_PARSING_FAILED);
        }

        // Step 3: Initialize new cipher for encryption
        boolean invalidateOnEnrollment = mPromptInfo.invalidateOnEnrollment();
        Cipher encryptCipher = mCryptographyManager.getInitializedCipherForEncryption(
            SECRET_KEY, invalidateOnEnrollment, this);

        // Step 4: Encrypt with new cipher and save
        EncryptedData encryptedData = mCryptographyManager.encryptData(password, encryptCipher);
        encryptedData.save(this);

        // Step 5: Return the migrated password
        Intent intent = new Intent();
        intent.putExtra(PromptInfo.SECRET_EXTRA, password);
        return intent;
    }

    private static final String CREDENTIAL_DELIMITER = "|:|";
    private String getPassword(String secret) {
        Pattern pattern = Pattern.compile(Pattern.quote(CREDENTIAL_DELIMITER));
        String[] credentialArray = pattern.split(secret);
        if (credentialArray.length == 2) {
            return credentialArray[1];
        } else {
            credentialArray = secret.split(":");
            if (credentialArray.length == 2) {
                return credentialArray[1];
            }
        }
        return null;
    }

    private Intent getDecryptedIntent(BiometricPrompt.CryptoObject cryptoObject) throws CryptoException {
        String token = this.mPromptInfo.getToken();
        byte[] ciphertext;
        if (token != null) {
            ciphertext = Base64.decode(token, Base64.NO_WRAP);
        } else {
            ciphertext = EncryptedData.loadCiphertext(this);
        }

        String secret = mCryptographyManager.decryptData(ciphertext, cryptoObject.getCipher());
        if (secret != null) {
            if (token != null) {
                secret = getPassword(secret);
                if (secret == null) {
                    return null;
                }
            }

            Intent intent = new Intent();
            intent.putExtra(PromptInfo.SECRET_EXTRA, secret);
            return intent;
        }
        return null;
    }

    private void finishWithError(CryptoException e) {
        finishWithError(e.getError().getValue(), e.getMessage());
    }

    private void finishWithError(PluginError error) {
        finishWithError(error.getValue(), error.getMessage());
    }

    private void finishWithError(PluginError error, String message) {
        finishWithError(error.getValue(), message);
    }

    private void finishWithError(int code, String message) {
        Intent data = new Intent();
        data.putExtra("code", code);
        data.putExtra("message", message);
        setResult(RESULT_CANCELED, data);
        finish();
    }
}
