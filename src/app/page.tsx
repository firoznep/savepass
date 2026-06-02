"use client";

import React, { useState, useEffect } from "react";
import { deriveKeys, encryptText, decryptText } from "@/utils/crypto";

interface ApiVaultItem {
  id: string;
  key_ciphertext: string;
  key_iv: string;
  value_ciphertext: string;
  value_iv: string;
  notes_ciphertext: string | null;
  notes_iv: string | null;
  created_at: string;
  updated_at: string;
}

interface DecryptedVaultItem {
  id: string;
  key: string;
  value: string;
  notes: string;
  created_at: string;
  updated_at: string;
  isVisible: boolean; // whether the value is currently unmasked
}

export default function SafePassApp() {
  const browserCryptoError =
    "Secure browser cryptography is unavailable. Open this app over HTTPS, or use localhost for development.";

  // Authentication & Cryptography State
  const [user, setUser] = useState<{ id: string; email: string } | null>(null);
  const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
  const [isCryptoAvailable, setIsCryptoAvailable] = useState<boolean | null>(
    null,
  );
  const [isAppLoading, setIsAppLoading] = useState(true);
  const [isDerivingKey, setIsDerivingKey] = useState(false);
  const [viewState, setViewState] = useState<"login" | "register" | "unlock">(
    "login",
  );

  // Auth Form State
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [authSuccess, setAuthSuccess] = useState("");

  // Vault Items State
  const [vaultItems, setVaultItems] = useState<DecryptedVaultItem[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [vaultError, setVaultError] = useState("");
  const [isVaultLoading, setIsVaultLoading] = useState(false);
  const [copiedItemId, setCopiedItemId] = useState<string | null>(null);

  // Add/Edit Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"add" | "edit">("add");
  const [editingItemId, setEditingItemId] = useState<string | null>(null);
  const [entryKey, setEntryKey] = useState("");
  const [entryValue, setEntryValue] = useState("");
  const [entryNotes, setEntryNotes] = useState("");
  const [modalError, setModalError] = useState("");
  const [isSavingEntry, setIsSavingEntry] = useState(false);

  // Password Generator State
  const [genLength, setGenLength] = useState(16);
  const [genUppercase, setGenUppercase] = useState(true);
  const [genNumbers, setGenNumbers] = useState(true);
  const [genSymbols, setGenSymbols] = useState(true);

  // Check if session is already active on mount
  useEffect(() => {
    setIsCryptoAvailable(
      window.isSecureContext && Boolean(window.crypto?.subtle),
    );

    async function checkSession() {
      try {
        const res = await fetch("/api/auth/me");
        if (res.ok) {
          const data = await res.json();
          setUser(data.user);
          setViewState("unlock"); // Session exists, prompt for master password to unlock
          setEmail(data.user.email);
        } else {
          setViewState("login");
        }
      } catch (err) {
        console.error("Session check error:", err);
      } finally {
        setIsAppLoading(false);
      }
    }
    checkSession();
  }, []);

  // Fetch and decrypt vault items
  const fetchVault = async (key: CryptoKey) => {
    setIsVaultLoading(true);
    setVaultError("");
    try {
      const res = await fetch("/api/vault");
      if (!res.ok) {
        throw new Error("Failed to retrieve vault data.");
      }
      const data = await res.json();
      const encryptedItems: ApiVaultItem[] = data.items;

      // Decrypt items in memory
      const decrypted = await Promise.all(
        encryptedItems.map(async (item) => {
          try {
            const keyText = await decryptText(
              item.key_ciphertext,
              item.key_iv,
              key,
            );
            const valueText = await decryptText(
              item.value_ciphertext,
              item.value_iv,
              key,
            );
            let notesText = "";
            if (item.notes_ciphertext && item.notes_iv) {
              notesText = await decryptText(
                item.notes_ciphertext,
                item.notes_iv,
                key,
              );
            }
            return {
              id: item.id,
              key: keyText,
              value: valueText,
              notes: notesText,
              created_at: item.created_at,
              updated_at: item.updated_at,
              isVisible: false,
            };
          } catch (decErr) {
            console.error("Decryption failed for item", item.id, decErr);
            return {
              id: item.id,
              key: "[Decryption Error]",
              value: "[Decryption Error]",
              notes:
                "Failed to decrypt this entry with the current master key.",
              created_at: item.created_at,
              updated_at: item.updated_at,
              isVisible: false,
            };
          }
        }),
      );

      setVaultItems(decrypted);
    } catch (err: any) {
      setVaultError(err.message || "An error occurred fetching vault.");
    } finally {
      setIsVaultLoading(false);
    }
  };

  // Perform client-side registration
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setAuthSuccess("");

    if (!email || !password || !confirmPassword) {
      setAuthError("All fields are required.");
      return;
    }

    if (password !== confirmPassword) {
      setAuthError("Passwords do not match.");
      return;
    }

    if (password.length < 8) {
      setAuthError("Master Password must be at least 8 characters long.");
      return;
    }

    if (isCryptoAvailable === false) {
      setAuthError(browserCryptoError);
      return;
    }

    setIsDerivingKey(true);

    try {
      // Derive PBKDF2 keys
      const {
        encryptionKey: derivedKey,
        authHash,
        keyDerivationSalt,
      } = await deriveKeys(password, email);

      const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          passwordHash: authHash,
          keyDerivationSalt,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Registration failed.");
      }

      setAuthSuccess("Registration successful! Logging you in...");

      // Auto login after registration
      const loginResponse = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          passwordHash: authHash,
        }),
      });

      const loginData = await loginResponse.json();

      if (!loginResponse.ok) {
        throw new Error(loginData.error || "Login failed.");
      }

      setUser(loginData.user);
      setEncryptionKey(derivedKey);
      setViewState("unlock"); // Just to update correctly, then fetch vault
      await fetchVault(derivedKey);

      // Clear forms
      setPassword("");
      setConfirmPassword("");
    } catch (err: any) {
      setAuthError(err.message || "An error occurred during registration.");
    } finally {
      setIsDerivingKey(false);
    }
  };

  // Perform client-side login or unlock
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");

    if (!email || !password) {
      setAuthError("Email and Master Password are required.");
      return;
    }

    if (isCryptoAvailable === false) {
      setAuthError(browserCryptoError);
      return;
    }

    setIsDerivingKey(true);

    try {
      // Fetch user's salt (or mock salt)
      const saltRes = await fetch(
        `/api/auth/salt?email=${encodeURIComponent(email)}`,
      );
      if (!saltRes.ok) {
        throw new Error("Failed to retrieve security salt.");
      }
      const saltData = await saltRes.json();
      const salt = saltData.salt;

      // Derive key client-side using retrieved salt
      const { encryptionKey: derivedKey, authHash } = await deriveKeys(
        password,
        email,
      );

      // Authenticate with server
      const loginRes = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          passwordHash: authHash,
        }),
      });

      const loginData = await loginRes.json();

      if (!loginRes.ok) {
        throw new Error(loginData.error || "Invalid credentials.");
      }

      setUser(loginData.user);
      setEncryptionKey(derivedKey);
      await fetchVault(derivedKey);

      // Clear forms
      setPassword("");
    } catch (err: any) {
      setAuthError(err.message || "Authentication failed.");
    } finally {
      setIsDerivingKey(false);
    }
  };

  // Log out
  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      setUser(null);
      setEncryptionKey(null);
      setVaultItems([]);
      setEmail("");
      setPassword("");
      setViewState("login");
    } catch (err) {
      console.error("Logout error:", err);
    }
  };

  // Open modal to add new item
  const openAddModal = () => {
    setModalMode("add");
    setEditingItemId(null);
    setEntryKey("");
    setEntryValue("");
    setEntryNotes("");
    setModalError("");
    setIsModalOpen(true);
  };

  // Open modal to edit existing item
  const openEditModal = (item: DecryptedVaultItem) => {
    setModalMode("edit");
    setEditingItemId(item.id);
    setEntryKey(item.key);
    setEntryValue(item.value);
    setEntryNotes(item.notes);
    setModalError("");
    setIsModalOpen(true);
  };

  // Encrypt and save entry (Add or Edit)
  const handleSaveEntry = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError("");

    if (!entryKey || !entryValue) {
      setModalError("Label/Service Name and Password/Value are required.");
      return;
    }

    if (!encryptionKey) {
      setModalError("Session encryption key missing. Please relog.");
      return;
    }

    setIsSavingEntry(true);

    try {
      // Encrypt details in-browser
      const encryptedKey = await encryptText(entryKey, encryptionKey);
      const encryptedValue = await encryptText(entryValue, encryptionKey);

      let encryptedNotes = null;
      if (entryNotes) {
        encryptedNotes = await encryptText(entryNotes, encryptionKey);
      }

      const bodyData = {
        keyCiphertext: encryptedKey.ciphertext,
        keyIv: encryptedKey.iv,
        valueCiphertext: encryptedValue.ciphertext,
        valueIv: encryptedValue.iv,
        notesCiphertext: encryptedNotes ? encryptedNotes.ciphertext : null,
        notesIv: encryptedNotes ? encryptedNotes.iv : null,
      };

      let url = "/api/vault";
      let method = "POST";

      if (modalMode === "edit" && editingItemId) {
        url = `/api/vault/${editingItemId}`;
        method = "PUT";
      }

      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyData),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to save entry.");
      }

      // Close modal and refresh vault
      setIsModalOpen(false);
      await fetchVault(encryptionKey);
    } catch (err: any) {
      setModalError(err.message || "An error occurred saving vault entry.");
    } finally {
      setIsSavingEntry(false);
    }
  };

  // Delete vault item
  const handleDeleteItem = async (id: string) => {
    if (
      !confirm(
        "Are you sure you want to delete this credentials item? This action is permanent.",
      )
    ) {
      return;
    }

    try {
      const res = await fetch(`/api/vault/${id}`, {
        method: "DELETE",
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to delete entry.");
      }

      // Filter local state
      setVaultItems(vaultItems.filter((item) => item.id !== id));
    } catch (err: any) {
      alert(err.message || "An error occurred deleting item.");
    }
  };

  // Copy text to clipboard and trigger animation
  const copyToClipboard = (text: string, itemId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItemId(itemId);
    setTimeout(() => {
      setCopiedItemId(null);
    }, 2000);
  };

  // Toggle visual mask on credentials
  const toggleVisibility = (id: string) => {
    setVaultItems(
      vaultItems.map((item) =>
        item.id === id ? { ...item, isVisible: !item.isVisible } : item,
      ),
    );
  };

  // Password Generator logic
  const generatePassword = () => {
    const lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    const uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numberChars = "0123456789";
    const symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let allowedChars = lowercaseChars;
    if (genUppercase) allowedChars += uppercaseChars;
    if (genNumbers) allowedChars += numberChars;
    if (genSymbols) allowedChars += symbolChars;

    let generated = "";
    const array = new Uint32Array(genLength);
    if (typeof window !== "undefined") {
      window.crypto.getRandomValues(array);
      for (let i = 0; i < genLength; i++) {
        generated += allowedChars.charAt(array[i] % allowedChars.length);
      }
    }
    setEntryValue(generated);
  };

  // Search filter
  const filteredItems = vaultItems.filter((item) =>
    item.key.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  // App Loading Spinner
  if (isAppLoading) {
    return (
      <div className="auth-wrapper">
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "1rem",
          }}
        >
          <div
            className="spinner"
            style={{ width: "40px", height: "40px", borderWidth: "3px" }}
          ></div>
          <p style={{ color: "var(--text-secondary)" }}>
            Securing your environment...
          </p>
        </div>
      </div>
    );
  }

  // RENDER: Auth Flow (Login & Register)
  if (!encryptionKey) {
    return (
      <div className="auth-wrapper">
        <div className="glass-card auth-card animate-fade-in">
          <div className="auth-header">
            <div className="auth-logo">SafePass</div>
            <div className="auth-subtitle">
              {viewState === "unlock"
                ? "Your personal vault is locked"
                : viewState === "register"
                  ? "Create a secure personal vault"
                  : "Access your credentials vault"}
            </div>
          </div>

          {isCryptoAvailable === false && (
            <div className="alert alert-danger">{browserCryptoError}</div>
          )}
          {authError && <div className="alert alert-danger">{authError}</div>}
          {authSuccess && (
            <div className="alert alert-success">{authSuccess}</div>
          )}

          {viewState === "unlock" ? (
            <form onSubmit={handleLogin}>
              <div className="alert alert-info">
                🔒 Your session is active. Enter your Master Password to decrypt
                your vault items.
              </div>
              <div className="form-group">
                <label htmlFor="unlock-password">Master Password</label>
                <input
                  type="password"
                  id="unlock-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••••••"
                  autoFocus
                  required
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: "100%", marginTop: "1rem" }}
                disabled={isDerivingKey || isCryptoAvailable === false}
              >
                {isDerivingKey ? (
                  <>
                    <span className="spinner"></span> Deriving Secure Keys...
                  </>
                ) : (
                  "Decrypt & Unlock Vault"
                )}
              </button>

              <div
                style={{
                  display: "flex",
                  justifyContent: "center",
                  marginTop: "1.5rem",
                }}
              >
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ width: "100%" }}
                  onClick={handleLogout}
                >
                  Log Out Session
                </button>
              </div>
            </form>
          ) : viewState === "register" ? (
            <form onSubmit={handleRegister}>
              <div className="form-group">
                <label htmlFor="reg-email">Email Address</label>
                <input
                  type="email"
                  id="reg-email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@domain.com"
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="reg-password">Master Password</label>
                <input
                  type="password"
                  id="reg-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min 8 chars, make it complex"
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="reg-confirm">Confirm Master Password</label>
                <input
                  type="password"
                  id="reg-confirm"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat master password"
                  required
                />
              </div>

              <div
                className="alert alert-info"
                style={{ fontSize: "0.8rem", marginTop: "1rem" }}
              >
                ⚠️ <strong>Zero Knowledge Alert:</strong> All encryption keys
                are derived client-side. If you forget your master password,
                your passwords cannot be recovered.
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: "100%", marginTop: "1rem" }}
                disabled={isDerivingKey || isCryptoAvailable === false}
              >
                {isDerivingKey ? (
                  <>
                    <span className="spinner"></span> Deriving Secure Keys...
                  </>
                ) : (
                  "Create Secure Vault"
                )}
              </button>

              <div className="auth-footer">
                Already have a vault?
                <a
                  href="#"
                  className="auth-link"
                  onClick={(e) => {
                    e.preventDefault();
                    setViewState("login");
                    setAuthError("");
                  }}
                >
                  Sign In
                </a>
              </div>
            </form>
          ) : (
            <form onSubmit={handleLogin}>
              <div className="form-group">
                <label htmlFor="login-email">Email Address</label>
                <input
                  type="email"
                  id="login-email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@domain.com"
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="login-password">Master Password</label>
                <input
                  type="password"
                  id="login-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: "100%", marginTop: "1rem" }}
                disabled={isDerivingKey || isCryptoAvailable === false}
              >
                {isDerivingKey ? (
                  <>
                    <span className="spinner"></span> Deriving Secure Keys...
                  </>
                ) : (
                  "Open Secure Vault"
                )}
              </button>

              <div className="auth-footer">
                First time?
                <a
                  href="#"
                  className="auth-link"
                  onClick={(e) => {
                    e.preventDefault();
                    setViewState("register");
                    setAuthError("");
                  }}
                >
                  Create Vault Account
                </a>
              </div>
            </form>
          )}
        </div>
      </div>
    );
  }

  // RENDER: Dashboard Flow
  return (
    <div className="container animate-fade-in">
      {/* Header */}
      <header className="app-header">
        <div className="app-brand">
          <svg
            style={{ width: "32px", height: "32px", fill: "var(--primary)" }}
            viewBox="0 0 24 24"
          >
            <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z" />
          </svg>
          <span className="app-logo">SafePass</span>
        </div>
        <div className="app-user-badge">
          <span className="user-email">🔓 {user?.email}</span>
          <button
            className="btn btn-secondary btn-icon"
            onClick={handleLogout}
            title="Log Out Session"
          >
            <svg
              style={{ width: "18px", height: "18px", fill: "currentColor" }}
              viewBox="0 0 24 24"
            >
              <path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z" />
            </svg>
          </button>
        </div>
      </header>

      {/* Main Content Action Row */}
      <div className="dashboard-actions">
        <div className="search-wrapper">
          <input
            type="text"
            className="search-input"
            placeholder="Search credentials label/service..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <span className="search-icon">
            <svg
              style={{ width: "18px", height: "18px", fill: "currentColor" }}
              viewBox="0 0 24 24"
            >
              <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z" />
            </svg>
          </span>
        </div>
        <button className="btn btn-primary" onClick={openAddModal}>
          <svg
            style={{ width: "18px", height: "18px", fill: "currentColor" }}
            viewBox="0 0 24 24"
          >
            <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" />
          </svg>
          Add Credentials
        </button>
      </div>

      {vaultError && (
        <div className="alert alert-danger" style={{ marginBottom: "2rem" }}>
          {vaultError}
          <button
            className="btn btn-secondary"
            onClick={() => encryptionKey && fetchVault(encryptionKey)}
            style={{
              padding: "0.25rem 0.5rem",
              fontSize: "0.8rem",
              marginLeft: "auto",
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* Grid displaying vault items */}
      {isVaultLoading ? (
        <div
          style={{ display: "flex", justifyContent: "center", padding: "4rem" }}
        >
          <div
            className="spinner"
            style={{ width: "32px", height: "32px", borderWidth: "3px" }}
          ></div>
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="glass-card empty-state">
          <div className="empty-state-icon">🛡️</div>
          <h3 className="empty-state-title">
            {searchTerm
              ? "No search results found"
              : "Your credentials vault is empty"}
          </h3>
          <p style={{ color: "var(--text-secondary)" }}>
            {searchTerm
              ? "Try adjusting your search filter keywords."
              : "Add your first encrypted credentials item to get started."}
          </p>
          {!searchTerm && (
            <button
              className="btn btn-primary"
              onClick={openAddModal}
              style={{ marginTop: "1.5rem" }}
            >
              Add Credentials Card
            </button>
          )}
        </div>
      ) : (
        <div className="vault-grid">
          {filteredItems.map((item) => (
            <div
              key={item.id}
              className="glass-card vault-item animate-fade-in"
            >
              <div>
                <div className="vault-item-header">
                  <h4 className="vault-item-title" title={item.key}>
                    {item.key}
                  </h4>
                  <div className="vault-item-actions">
                    <button
                      className="btn-icon btn"
                      onClick={() => openEditModal(item)}
                      title="Edit Item"
                    >
                      <svg
                        style={{
                          width: "16px",
                          height: "16px",
                          fill: "currentColor",
                        }}
                        viewBox="0 0 24 24"
                      >
                        <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" />
                      </svg>
                    </button>
                    <button
                      className="btn-icon btn"
                      style={{ color: "var(--error)" }}
                      onClick={() => handleDeleteItem(item.id)}
                      title="Delete Item"
                    >
                      <svg
                        style={{
                          width: "16px",
                          height: "16px",
                          fill: "currentColor",
                        }}
                        viewBox="0 0 24 24"
                      >
                        <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
                      </svg>
                    </button>
                  </div>
                </div>

                <div className="vault-item-content">
                  <div className="vault-field">
                    <span
                      className={`vault-field-value ${!item.isVisible ? "hidden-pass" : ""}`}
                    >
                      {item.isVisible ? item.value : "••••••••••••"}
                    </span>
                    <div style={{ display: "flex", gap: "0.25rem" }}>
                      <button
                        className="btn btn-icon"
                        onClick={() => toggleVisibility(item.id)}
                        title={
                          item.isVisible ? "Hide Password" : "Show Password"
                        }
                        style={{ padding: "0.25rem" }}
                      >
                        {item.isVisible ? (
                          <svg
                            style={{
                              width: "16px",
                              height: "16px",
                              fill: "currentColor",
                            }}
                            viewBox="0 0 24 24"
                          >
                            <path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.82l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.74-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z" />
                          </svg>
                        ) : (
                          <svg
                            style={{
                              width: "16px",
                              height: "16px",
                              fill: "currentColor",
                            }}
                            viewBox="0 0 24 24"
                          >
                            <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z" />
                          </svg>
                        )}
                      </button>
                      <button
                        className="btn btn-icon"
                        onClick={() => copyToClipboard(item.value, item.id)}
                        title="Copy Password"
                        style={{ padding: "0.25rem" }}
                      >
                        {copiedItemId === item.id ? (
                          <svg
                            style={{
                              width: "16px",
                              height: "16px",
                              fill: "var(--success)",
                            }}
                            viewBox="0 0 24 24"
                          >
                            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
                          </svg>
                        ) : (
                          <svg
                            style={{
                              width: "16px",
                              height: "16px",
                              fill: "currentColor",
                            }}
                            viewBox="0 0 24 24"
                          >
                            <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z" />
                          </svg>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {item.notes && (
                <div className="vault-item-notes">
                  <strong>Notes:</strong> {item.notes}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Modal - Add / Edit Credentials */}
      {isModalOpen && (
        <div className="modal-overlay">
          <div className="glass-card modal-content animate-fade-in">
            <div className="modal-header">
              <h3 className="modal-title">
                {modalMode === "add"
                  ? "Add Credentials Card"
                  : "Edit Credentials Card"}
              </h3>
              <button
                className="btn btn-icon"
                onClick={() => setIsModalOpen(false)}
              >
                <svg
                  style={{
                    width: "20px",
                    height: "20px",
                    fill: "currentColor",
                  }}
                  viewBox="0 0 24 24"
                >
                  <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
                </svg>
              </button>
            </div>

            {modalError && (
              <div className="alert alert-danger">{modalError}</div>
            )}

            <form onSubmit={handleSaveEntry}>
              <div className="form-group">
                <label htmlFor="entry-key">Label / Service Name</label>
                <input
                  type="text"
                  id="entry-key"
                  value={entryKey}
                  onChange={(e) => setEntryKey(e.target.value)}
                  placeholder="e.g. Google, GitHub, Bank Account"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="entry-val">Password / Value</label>
                <div className="generator-output-wrapper">
                  <input
                    type="text"
                    id="entry-val"
                    value={entryValue}
                    onChange={(e) => setEntryValue(e.target.value)}
                    placeholder="Enter password or value"
                    required
                  />
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={generatePassword}
                    title="Generate secure password"
                    style={{ padding: "0 1rem" }}
                  >
                    🎲
                  </button>
                </div>
              </div>

              {/* Password Generator Options */}
              <div className="generator-section">
                <div className="generator-title">
                  🛡️ Generate Password Settings
                </div>
                <div className="generator-slider-group">
                  <label htmlFor="gen-len">Length: {genLength}</label>
                  <input
                    type="range"
                    id="gen-len"
                    min="8"
                    max="64"
                    value={genLength}
                    onChange={(e) => setGenLength(parseInt(e.target.value, 10))}
                  />
                </div>
                <div className="generator-settings">
                  <label className="generator-checkbox">
                    <input
                      type="checkbox"
                      checked={genUppercase}
                      onChange={(e) => setGenUppercase(e.target.checked)}
                    />
                    A-Z
                  </label>
                  <label className="generator-checkbox">
                    <input
                      type="checkbox"
                      checked={genNumbers}
                      onChange={(e) => setGenNumbers(e.target.checked)}
                    />
                    0-9
                  </label>
                  <label className="generator-checkbox">
                    <input
                      type="checkbox"
                      checked={genSymbols}
                      onChange={(e) => setGenSymbols(e.target.checked)}
                    />
                    !@#
                  </label>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="entry-notes">Notes (Optional)</label>
                <textarea
                  id="entry-notes"
                  value={entryNotes}
                  onChange={(e) => setEntryNotes(e.target.value)}
                  placeholder="Username, login link, security questions, etc. (will also be fully encrypted)"
                  rows={3}
                />
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setIsModalOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isSavingEntry}
                >
                  {isSavingEntry ? (
                    <>
                      <span className="spinner"></span> Saving...
                    </>
                  ) : (
                    "Save Securely"
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
