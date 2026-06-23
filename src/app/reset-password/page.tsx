"use client";

import React, { useEffect, useState } from "react";
import {
  deriveKeys,
  deriveRecoveryKeys,
  unwrapMasterKeyWithRecovery,
  wrapVaultKeyWithPassword,
  wrapMasterKeyWithRecovery,
  bytesToBase64,
} from "@/utils/crypto";

export default function ResetPasswordPage() {
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [status, setStatus] = useState<
    "loading" | "ready" | "invalid-link" | "no-recovery" | "error" | "completed"
  >("loading");
  const [serverError, setServerError] = useState<string>("");
  const [info, setInfo] = useState<string>("");

  const [recoveryCiphertext, setRecoveryCiphertext] = useState<string | null>(
    null,
  );
  const [recoveryIv, setRecoveryIv] = useState<string | null>(null);
  const [recoverySalt, setRecoverySalt] = useState<string | null>(null);

  const [recoveryCode, setRecoveryCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [newRecoveryCode, setNewRecoveryCode] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const params = new URLSearchParams(window.location.search);
    const tokenParam = params.get("token");
    const emailParam = params.get("email");

    if (!tokenParam || !emailParam) {
      setStatus("invalid-link");
      return;
    }

    setToken(tokenParam);
    setEmail(emailParam.toLowerCase().trim());
    verifyReset(tokenParam, emailParam.toLowerCase().trim());
  }, []);

  const verifyReset = async (tokenValue: string, emailValue: string) => {
    try {
      const response = await fetch("/api/auth/verify-reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailValue, token: tokenValue }),
      });

      const data = await response.json();
      if (!response.ok) {
        setServerError(data.error || "Invalid or expired reset link.");
        setStatus("error");
        return;
      }

      const wrapped = data.wrapped;
      if (
        wrapped?.recoveryCiphertext &&
        wrapped?.recoveryIv &&
        wrapped?.recoverySalt
      ) {
        setRecoveryCiphertext(wrapped.recoveryCiphertext);
        setRecoveryIv(wrapped.recoveryIv);
        setRecoverySalt(wrapped.recoverySalt);
        setInfo(
          "Enter your recovery code and set a new master password to recover your vault.",
        );
        setStatus("ready");
      } else {
        setInfo(
          "This account has no recovery code configured. Vault recovery is not possible with email reset alone.",
        );
        setStatus("no-recovery");
      }
    } catch (err: any) {
      setServerError(err.message || "Unable to verify reset link.");
      setStatus("error");
    }
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setServerError("");
    setSuccessMessage("");

    if (status !== "ready") {
      return;
    }

    if (!recoveryCode || !newPassword || !confirmPassword) {
      setServerError("All fields are required.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setServerError("New password and confirmation do not match.");
      return;
    }

    if (!email || !token) {
      setServerError("Missing reset parameters.");
      return;
    }

    if (!recoveryCiphertext || !recoveryIv || !recoverySalt) {
      setServerError("Recovery information is missing.");
      return;
    }

    setIsSubmitting(true);

    try {
      const { encryptionKey: recoveryKey } = await deriveRecoveryKeys(
        recoveryCode,
        email,
      );

      const unwrapped = await unwrapMasterKeyWithRecovery(
        recoveryKey,
        recoveryCiphertext,
        recoveryIv,
      );

      const vaultKeyBase64 = bytesToBase64(unwrapped.bytes);

      const {
        encryptionKey: passwordKey,
        authHash: newPasswordHash,
        keyDerivationSalt: newKeyDerivationSalt,
      } = await deriveKeys(newPassword, email);

      const wrappedVaultKey = await wrapVaultKeyWithPassword(
        passwordKey,
        vaultKeyBase64,
      );

      const requestBody: any = {
        email,
        token,
        newPasswordHash,
        newKeyDerivationSalt,
        vaultKeyCiphertext: wrappedVaultKey.ciphertext,
        vaultKeyIv: wrappedVaultKey.iv,
      };

      if (newRecoveryCode && newRecoveryCode.trim().length > 0) {
        const {
          encryptionKey: newRecoveryKey,
          authHash: recoveryAuthHash,
          keyDerivationSalt: recoveryKeyDerivationSalt,
        } = await deriveRecoveryKeys(newRecoveryCode, email);

        const wrappedRecovery = await wrapMasterKeyWithRecovery(
          newRecoveryKey,
          vaultKeyBase64,
        );

        requestBody.recoveryCiphertext = wrappedRecovery.ciphertext;
        requestBody.recoveryIv = wrappedRecovery.iv;
        requestBody.recoverySalt = recoveryKeyDerivationSalt;
        requestBody.recoveryAuthHash = recoveryAuthHash;
      }

      const resetResponse = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      const resetData = await resetResponse.json();
      if (!resetResponse.ok) {
        throw new Error(
          resetData.error || "Unable to complete password reset.",
        );
      }

      setSuccessMessage(
        "Password reset successfully. You can now sign in with your new password.",
      );
      setStatus("completed");
    } catch (err: any) {
      setServerError(
        err.message ||
          "Recovery failed. Check your recovery code and try again.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-wrapper">
      <div className="glass-card auth-card animate-fade-in">
        <div className="auth-header">
          <div className="auth-logo">SafePass</div>
          <div className="auth-subtitle">Reset your vault access</div>
        </div>

        {(status === "loading" ||
          status === "error" ||
          status === "invalid-link") && (
          <div className="alert alert-info">
            {status === "loading"
              ? "Verifying your reset link..."
              : status === "invalid-link"
                ? "Invalid password reset link."
                : serverError || "Unable to process this reset request."}
          </div>
        )}

        {status === "no-recovery" && (
          <>
            <div className="alert alert-warning">{info}</div>
            <p>
              If you did not configure a recovery code when you registered, the
              vault cannot be recovered from this reset link.
            </p>
            <p>
              You may sign in with your existing password if you remember it, or
              create a new account to start fresh.
            </p>
            <a className="btn btn-secondary" href="/">
              Back to Sign In
            </a>
          </>
        )}

        {status === "ready" && (
          <form onSubmit={handleSubmit}>
            {info && <div className="alert alert-info">{info}</div>}
            {serverError && (
              <div className="alert alert-danger">{serverError}</div>
            )}
            {successMessage && (
              <div className="alert alert-success">{successMessage}</div>
            )}

            <div className="form-group">
              <label htmlFor="reset-recovery-code">Recovery Code</label>
              <input
                type="password"
                id="reset-recovery-code"
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value)}
                placeholder="Enter your recovery code"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="reset-new-password">New Master Password</label>
              <input
                type="password"
                id="reset-new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New master password"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="reset-confirm-password">
                Confirm New Master Password
              </label>
              <input
                type="password"
                id="reset-confirm-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="reset-new-recovery">
                New Recovery Code (optional)
              </label>
              <input
                type="password"
                id="reset-new-recovery"
                value={newRecoveryCode}
                onChange={(e) => setNewRecoveryCode(e.target.value)}
                placeholder="Enter a new recovery code or leave blank"
              />
              <small style={{ color: "var(--text-secondary)" }}>
                Optional: set a new recovery code, then store it safely offline.
              </small>
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={isSubmitting}
              style={{ width: "100%", marginTop: "1rem" }}
            >
              {isSubmitting ? "Applying Reset..." : "Reset Password"}
            </button>

            <div className="auth-footer" style={{ marginTop: "1rem" }}>
              <a className="auth-link" href="/">
                Back to Sign In
              </a>
            </div>
          </form>
        )}

        {status === "completed" && (
          <>
            <div className="alert alert-success">{successMessage}</div>
            <a className="btn btn-primary" href="/">
              Return to Sign In
            </a>
          </>
        )}
      </div>
    </div>
  );
}
