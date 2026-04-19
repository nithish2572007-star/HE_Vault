#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <limits>
#include <map>
#include <filesystem>

// Crypto headers
#include <seal/seal.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;
using namespace seal;

// --- Config & File Paths ---
const string PARAMS_FILE  = "params.bin";
const string PK_FILE      = "public_key.bin";
const string SK_ENC_FILE  = "secret_key.enc";
const string DATA_FILE    = "data_store.bin";

const int SALT_LEN      = 16;
const int IV_LEN        = 12;
const int TAG_LEN       = 16;
const int KEY_LEN       = 32;
const int PBKDF2_ITERS  = 100000;

// Maximum bytes accepted from any single getline() call.
// Prevents unbounded heap growth from malicious/accidental input.
const size_t MAX_INPUT_LEN = 1024;

// Temporary file used by rewriteVault() for atomic replacement.
const string TEMP_DATA_FILE = "data_store.bin.tmp";

// RAII wrapper so EVP_CIPHER_CTX is always freed, even if an exception
// propagates out of the crypto functions.
struct CtxGuard
{
    EVP_CIPHER_CTX* ctx;
    explicit CtxGuard() : ctx(EVP_CIPHER_CTX_new()) {}
    ~CtxGuard() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
};

// FIX (Low): helper to securely erase sensitive string data from heap memory
// before it goes out of scope.  std::string destructor is not guaranteed to
// zero memory in optimised builds.
static void secureErase(string& s)
{
    if (!s.empty())
        OPENSSL_cleanse(&s[0], s.size());
}

// Read one line from stdin, capped at MAX_INPUT_LEN bytes.
// Returns false if the input exceeded the limit (line is cleared).
static bool safeGetline(string& out)
{
    if (!getline(cin, out))
        return false;
    if (out.length() > MAX_INPUT_LEN)
    {
        cout << "[-] Error: Input exceeds maximum allowed length (" << MAX_INPUT_LEN << " bytes).\n";
        out.clear();
        return false;
    }
    return true;
}

class CryptoManager
{
public:
    static void handleErrors()
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    static void deriveKey(const string& password, const unsigned char* salt, unsigned char* key)
    {
        if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                                salt, SALT_LEN, PBKDF2_ITERS,
                                EVP_sha256(), KEY_LEN, key))
        {
            handleErrors();
        }
    }

    static string encryptSK(const string& plaintext_sk, const string& password)
    {
        unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];

        // FIX (Low): check RAND_bytes return value — failure means the entropy
        // pool is not ready and the salt/IV would be uninitialised stack bytes.
        if (RAND_bytes(salt, SALT_LEN) != 1) handleErrors();
        if (RAND_bytes(iv,   IV_LEN)   != 1) handleErrors();
        deriveKey(password, salt, key);

        CtxGuard g;
        EVP_CIPHER_CTX* ctx = g.ctx;
        int len, ciphertext_len;
        vector<unsigned char> ciphertext(plaintext_sk.length() + EVP_MAX_BLOCK_LENGTH);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          (const unsigned char*)plaintext_sk.data(),
                          plaintext_sk.length());
        ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, (void*)tag);

        string out(reinterpret_cast<char*>(salt),              SALT_LEN);
        out.append(reinterpret_cast<char*>(iv),                IV_LEN);
        out.append(reinterpret_cast<char*>(tag),               TAG_LEN);
        out.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);

        return out;
    }

    static string decryptSK(const string& packaged_data, const string& password)
    {
        if (packaged_data.length() < (size_t)(SALT_LEN + IV_LEN + TAG_LEN))
            return "";

        unsigned char salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN], key[KEY_LEN];
        memcpy(salt, packaged_data.data(),                     SALT_LEN);
        memcpy(iv,   packaged_data.data() + SALT_LEN,          IV_LEN);
        memcpy(tag,  packaged_data.data() + SALT_LEN + IV_LEN, TAG_LEN);

        deriveKey(password, salt, key);

        const unsigned char* ciphertext =
            (const unsigned char*)(packaged_data.data() + SALT_LEN + IV_LEN + TAG_LEN);
        int ciphertext_len = (int)(packaged_data.length() - (SALT_LEN + IV_LEN + TAG_LEN));

        CtxGuard g;
        EVP_CIPHER_CTX* ctx = g.ctx;
        int len, plaintext_len;
        vector<unsigned char> plaintext(ciphertext_len);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
        plaintext_len = len;

        // (void*) cast is required by OpenSSL's API contract for SET_TAG.
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag);

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

        if (ret > 0)
        {
            plaintext_len += len;
            return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
        }
        return "";
    }
};

class Vault
{
private:
    shared_ptr<SEALContext> context_;

    void loadContext()
    {
        ifstream fs(PARAMS_FILE, ios::binary);
        if (!fs.is_open())
            throw runtime_error("[-] Error: Run setup first.");

        EncryptionParameters parms;
        parms.load(fs);
        context_ = make_shared<SEALContext>(parms);
    }

    string getRawSecretKey(const string& password)
    {
        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        if (!fs_sk.is_open())
            throw runtime_error("[-] Error: Vault does not exist. Run Setup first.");

        streamsize size = fs_sk.tellg();

        // FIX (Low): tellg() returns -1 on error; casting to size_t wraps it
        // to a huge value, causing bad_alloc or memory corruption.
        if (size <= 0)
            throw runtime_error("[-] Error: Could not read secret key file.");

        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        fs_sk.read(&enc_sk_data[0], size);

        string raw_sk = CryptoManager::decryptSK(enc_sk_data, password);
        if (raw_sk.empty())
            throw runtime_error("[-] Error: Incorrect password.");

        return raw_sk;
    }

    map<string, string> loadAllAccounts(const string& password)
    {
        string raw_sk = getRawSecretKey(password);

        stringstream sk_ss(raw_sk);
        SecretKey secret_key;
        secret_key.load(*context_, sk_ss);

        // Securely erase raw_sk now that SecretKey holds its own copy.
        secureErase(raw_sk);

        // Also zero the stringstream's internal buffer — it holds a copy of the
        // secret key bytes that secureErase(raw_sk) above does not reach.
        string sk_ss_buf = sk_ss.str();
        secureErase(sk_ss_buf);
        sk_ss.str(sk_ss_buf);   // replace buffer content with zeroed bytes

        Decryptor    decryptor(*context_, secret_key);
        BatchEncoder batch_encoder(*context_);

        ifstream fs_data(DATA_FILE, ios::binary);
        map<string, string> decrypted_accounts;

        if (!fs_data.is_open())
            return decrypted_accounts;

        while (fs_data.peek() != EOF)
        {
            try
            {
                Ciphertext encrypted_data;
                encrypted_data.load(*context_, fs_data);

                Plaintext plain_data;
                decryptor.decrypt(encrypted_data, plain_data);

                vector<uint64_t> pod_matrix;
                batch_encoder.decode(plain_data, pod_matrix);

                string decoded_str;
                for (uint64_t val : pod_matrix)
                {
                    if (val == 0) break;
                    decoded_str += static_cast<char>(val);
                }

                size_t delim_pos = decoded_str.find('|');
                if (delim_pos != string::npos)
                {
                    decrypted_accounts[decoded_str.substr(0, delim_pos)] =
                        decoded_str.substr(delim_pos + 1);
                }
            }
            catch (const exception&)
            {
                break;
            }
        }
        return decrypted_accounts;
    }

    void rewriteVault(const map<string, string>& accounts)
    {
        // Write to a temporary file first, then atomically rename it over the
        // real data file.  This eliminates the crash window that existed when
        // the old code truncated the file and then re-opened it for writing:
        // any failure between those two steps left the vault permanently empty.
        // rename(2) is atomic on POSIX filesystems, so readers either see the
        // complete old file or the complete new file — never a partial write.

        if (accounts.empty())
        {
            // Nothing to write: replace with an empty file atomically.
            {
                ofstream tmp(TEMP_DATA_FILE, ios::binary | ios::trunc);
                if (!tmp.is_open())
                    throw runtime_error("[-] Fatal: could not create temp vault file.");
            }
            filesystem::rename(TEMP_DATA_FILE, DATA_FILE);
            return;
        }

        ifstream fs_pk(PK_FILE, ios::binary);
        if (!fs_pk.is_open())
            throw runtime_error("[-] Fatal: could not open public key file.");

        PublicKey public_key;
        public_key.load(*context_, fs_pk);
        fs_pk.close();

        Encryptor    encryptor(*context_, public_key);
        BatchEncoder batch_encoder(*context_);
        size_t       slot_count = batch_encoder.slot_count();

        ofstream tmp(TEMP_DATA_FILE, ios::binary | ios::trunc);
        if (!tmp.is_open())
            throw runtime_error("[-] Fatal: could not create temp vault file.");

        for (const auto& pair : accounts)
        {
            string formatted_data = pair.first + "|" + pair.second;

            if (formatted_data.length() > slot_count)
                throw runtime_error("[-] Error: Payload exceeds max vault slot size.");

            vector<uint64_t> pod_matrix(slot_count, 0ULL);
            for (size_t i = 0; i < formatted_data.length() && i < slot_count; ++i)
                pod_matrix[i] = static_cast<uint64_t>(formatted_data[i]);

            Plaintext plain_data;
            batch_encoder.encode(pod_matrix, plain_data);

            Ciphertext encrypted_data;
            encryptor.encrypt(plain_data, encrypted_data);

            encrypted_data.save(tmp);
        }

        tmp.close();

        // Atomic swap: if this throws, the original DATA_FILE is untouched.
        error_code ec;
        filesystem::rename(TEMP_DATA_FILE, DATA_FILE, ec);
        if (ec)
            throw runtime_error("[-] Fatal: could not atomically replace vault file: " + ec.message());
    }

    // Shared input validation for account names and credentials.
    // Returns false and prints a message if the value is unsafe to store.
    static bool validateField(const string& value, const string& field_name)
    {
        if (value.empty())
        {
            cout << "[-] Error: " << field_name << " cannot be empty.\n";
            return false;
        }
        if (value.length() > MAX_INPUT_LEN)
        {
            cout << "[-] Error: " << field_name << " exceeds maximum length.\n";
            return false;
        }
        if (value.find('|') != string::npos)
        {
            cout << "[-] Error: " << field_name << " cannot contain the '|' character.\n";
            return false;
        }
        for (char c : value)
        {
            if (c == '\0')
            {
                cout << "[-] Error: " << field_name << " cannot contain null bytes.\n";
                return false;
            }
        }
        return true;
    }

public:

    void setup(const string& password)
    {
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 4096;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

        context_ = make_shared<SEALContext>(parms);

        // Create/truncate data file atomically via the temp path.
        {
            ofstream tmp(TEMP_DATA_FILE, ios::binary | ios::trunc);
        }
        filesystem::rename(TEMP_DATA_FILE, DATA_FILE);

        ofstream fs_params(PARAMS_FILE, ios::binary);
        parms.save(fs_params);
        fs_params.close();

        KeyGenerator keygen(*context_);
        SecretKey    secret_key = keygen.secret_key();
        PublicKey    public_key;
        keygen.create_public_key(public_key);

        ofstream fs_pk(PK_FILE, ios::binary);
        public_key.save(fs_pk);
        fs_pk.close();

        // Serialize SK to a stringstream, encrypt it, then zero the buffer.
        stringstream sk_ss;
        secret_key.save(sk_ss);

        string sk_plain = sk_ss.str();
        string enc_sk   = CryptoManager::encryptSK(sk_plain, password);
        secureErase(sk_plain);

        ofstream fs_sk(SK_ENC_FILE, ios::binary);
        fs_sk.write(enc_sk.data(), enc_sk.length());
        fs_sk.close();

        cout << "[+] Setup complete. Vault reset and new keys generated.\n";
    }

    void store(const string& account_name, const string& credentials, const string& password)
    {
        loadContext();

        // FIX (High): validate both fields — account_name null bytes cause
        // unparseable records; credentials were already guarded in v1.
        if (!validateField(account_name, "Account names"))   return;
        if (!validateField(credentials,  "Credentials"))     return;

        map<string, string> accounts = loadAllAccounts(password);

        if (accounts.find(account_name) != accounts.end())
        {
            cout << "[-] An account with the name '" << account_name << "' already exists.\n";
            cout << "Would you like to update it with these new credentials? (y/n): ";
            string response;
            getline(cin, response);

            if (response == "y" || response == "Y")
            {
                accounts[account_name] = credentials;
                rewriteVault(accounts);
                cout << "[+] Account '" << account_name << "' updated successfully.\n";
            }
            else
            {
                cout << "[-] Add operation cancelled.\n";
            }
            return;
        }

        string formatted_data = account_name + "|" + credentials;

        BatchEncoder batch_encoder(*context_);
        size_t       slot_count = batch_encoder.slot_count();

        if (formatted_data.length() > slot_count)
            throw runtime_error("[-] Error: Payload exceeds max vault slot size.");

        vector<uint64_t> pod_matrix(slot_count, 0ULL);
        for (size_t i = 0; i < formatted_data.length() && i < slot_count; ++i)
            pod_matrix[i] = static_cast<uint64_t>(formatted_data[i]);

        Plaintext plain_data;
        batch_encoder.encode(pod_matrix, plain_data);

        ifstream  fs_pk(PK_FILE, ios::binary);
        PublicKey public_key;
        public_key.load(*context_, fs_pk);

        Encryptor  encryptor(*context_, public_key);
        Ciphertext encrypted_data;
        encryptor.encrypt(plain_data, encrypted_data);

        ofstream fs_data(DATA_FILE, ios::binary | ios::app);
        encrypted_data.save(fs_data);

        cout << "[+] Account stored successfully.\n";
    }

    void retrieve(const string& password)
    {
        loadContext();
        map<string, string> decrypted_accounts = loadAllAccounts(password);

        if (decrypted_accounts.empty())
        {
            cout << "[-] No formatted accounts found.\n";
            return;
        }

        cout << "\n--- Available Accounts ---\n";
        for (const auto& pair : decrypted_accounts)
            cout << "- " << pair.first << "\n";
        cout << "--------------------------\n";

        cout << "Enter the name of the account to retrieve its credentials: ";
        string target_account;
        getline(cin, target_account);

        auto it = decrypted_accounts.find(target_account);
        if (it != decrypted_accounts.end())
        {
            cout << "\n[+] Credentials for '" << target_account << "': " << it->second << "\n";

            // FIX (Medium): credentials printed in plaintext persist on-screen
            // indefinitely.  Prompt the user to dismiss, then erase the lines.
            cout << "Press Enter to clear credentials from screen...";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            // Move up two lines and erase them (works on ANSI-compatible terminals).
            cout << "\033[1A\033[2K\033[1A\033[2K" << flush;
        }
        else
        {
            cout << "[-] Account '" << target_account << "' not found.\n";
        }
    }

    void updateAccount(const string& password)
    {
        loadContext();
        map<string, string> accounts = loadAllAccounts(password);

        if (accounts.empty())
        {
            cout << "[-] No formatted accounts found.\n";
            return;
        }

        cout << "\n--- Available Accounts ---\n";
        for (const auto& pair : accounts)
            cout << "- " << pair.first << "\n";
        cout << "--------------------------\n";

        cout << "Enter account name to update: ";
        string account_name;
        getline(cin, account_name);

        if (accounts.find(account_name) == accounts.end())
        {
            cout << "[-] Error: Account '" << account_name << "' not found.\n";
            return;
        }

        cout << "Enter new credentials: ";
        string new_credentials;
        getline(cin, new_credentials);

        if (!validateField(new_credentials, "Credentials"))
            return;

        accounts[account_name] = new_credentials;
        rewriteVault(accounts);

        cout << "[+] Account '" << account_name << "' updated successfully.\n";
    }

    void deleteAccount(const string& password)
    {
        loadContext();
        map<string, string> accounts = loadAllAccounts(password);

        if (accounts.empty())
        {
            cout << "[-] No formatted accounts found.\n";
            return;
        }

        cout << "\n--- Available Accounts ---\n";
        for (const auto& pair : accounts)
            cout << "- " << pair.first << "\n";
        cout << "--------------------------\n";

        cout << "Enter account name to delete: ";
        string account_name;
        getline(cin, account_name);

        if (accounts.find(account_name) == accounts.end())
        {
            cout << "[-] Error: Account '" << account_name << "' not found.\n";
            return;
        }

        accounts.erase(account_name);
        rewriteVault(accounts);

        cout << "[+] Account '" << account_name << "' deleted successfully.\n";
    }

    void changePassword(const string& old_pw, const string& new_pw)
    {
        // loadContext() is not required here — we only touch the SK file.
        string raw_sk = getRawSecretKey(old_pw);

        string   new_enc_sk = CryptoManager::encryptSK(raw_sk, new_pw);
        secureErase(raw_sk);   // FIX (Medium): erase SK bytes before leaving scope

        ofstream out_sk(SK_ENC_FILE, ios::binary | ios::trunc);
        out_sk.write(new_enc_sk.data(), new_enc_sk.length());

        cout << "[+] Password updated successfully.\n";
    }
};

int main()
{
    Vault vault;
    int   choice;

    while (true)
    {
        cout << "\n==============================\n";
        cout << "      SovereignVault CLI      \n";
        cout << "==============================\n";
        cout << "  1. Setup / Factory Reset\n";
        cout << "  2. Add Account\n";
        cout << "  3. Retrieve Credentials\n";
        cout << "  4. Update Account\n";
        cout << "  5. Delete Account\n";
        cout << "  6. Change Master Password\n";
        cout << "  7. Exit\n";
        cout << "==============================\n";
        cout << "> ";

        if (!(cin >> choice))
        {
            cin.clear();
            cin.ignore(10000, '\n');
            continue;
        }
        cin.ignore(10000, '\n');

        if (choice == 1)
        {
            cout << "WARNING: This will permanently erase all stored accounts and regenerate keys.\n";
            cout << "Type YES to confirm: ";
            string confirm;
            if (!safeGetline(confirm) || confirm != "YES")
            {
                cout << "[-] Reset cancelled.\n";
                continue;
            }

            // FIX: password confirmation loop — a typo on setup locks the vault
            // permanently since there is no recovery path without the password.
            string pw, pw_confirm;
            do {
                cout << "Enter new master password: ";
                if (!safeGetline(pw)) { pw.clear(); break; }

                if (pw.empty())
                {
                    cout << "[-] Error: Master password cannot be empty.\n";
                    continue;
                }

                cout << "Confirm master password: ";
                if (!safeGetline(pw_confirm)) { pw.clear(); break; }

                if (pw != pw_confirm)
                {
                    cout << "[-] Passwords do not match. Try again.\n";
                    secureErase(pw);
                    secureErase(pw_confirm);
                }
            } while (pw != pw_confirm || pw.empty());

            secureErase(pw_confirm);

            if (pw.empty())
            {
                cout << "[-] Setup cancelled.\n";
                continue;
            }

            try { vault.setup(pw); }
            catch (exception& e) { cout << e.what() << "\n"; }

            secureErase(pw);
        }
        else if (choice == 2)
        {
            string account_name, credentials, master_pw;

            cout << "Enter master password: ";
            if (!safeGetline(master_pw)) continue;

            cout << "Enter account name: ";
            if (!safeGetline(account_name)) { secureErase(master_pw); continue; }

            cout << "Enter credentials to store: ";
            if (!safeGetline(credentials)) { secureErase(master_pw); secureErase(account_name); continue; }

            try { vault.store(account_name, credentials, master_pw); }
            catch (exception& e) { cout << e.what() << "\n"; }

            // Securely erase all sensitive strings once the operation completes.
            secureErase(master_pw);
            secureErase(credentials);
            secureErase(account_name);
        }
        else if (choice == 3)
        {
            string pw;
            cout << "Enter master password: ";
            if (!safeGetline(pw)) continue;

            try { vault.retrieve(pw); }
            catch (exception& e) { cout << e.what() << "\n"; }

            secureErase(pw);
        }
        else if (choice == 4)
        {
            string master_pw;
            cout << "Enter master password: ";
            if (!safeGetline(master_pw)) continue;

            try { vault.updateAccount(master_pw); }
            catch (exception& e) { cout << e.what() << "\n"; }

            secureErase(master_pw);
        }
        else if (choice == 5)
        {
            string master_pw;
            cout << "Enter master password: ";
            if (!safeGetline(master_pw)) continue;

            try { vault.deleteAccount(master_pw); }
            catch (exception& e) { cout << e.what() << "\n"; }

            secureErase(master_pw);
        }
        else if (choice == 6)
        {
            string old_pw, new_pw, new_pw_confirm;

            cout << "Enter current password: ";
            if (!safeGetline(old_pw)) continue;

            // Confirmation loop for the new password, matching setup behaviour.
            do {
                cout << "Enter new password: ";
                if (!safeGetline(new_pw)) { new_pw.clear(); break; }

                if (new_pw.empty())
                {
                    cout << "[-] Error: New password cannot be empty.\n";
                    continue;
                }

                cout << "Confirm new password: ";
                if (!safeGetline(new_pw_confirm)) { new_pw.clear(); break; }

                if (new_pw != new_pw_confirm)
                {
                    cout << "[-] Passwords do not match. Try again.\n";
                    secureErase(new_pw);
                    secureErase(new_pw_confirm);
                }
            } while (new_pw != new_pw_confirm || new_pw.empty());

            secureErase(new_pw_confirm);

            if (!new_pw.empty())
            {
                try { vault.changePassword(old_pw, new_pw); }
                catch (exception& e) { cout << e.what() << "\n"; }
            }
            else
            {
                cout << "[-] Password change cancelled.\n";
            }

            secureErase(old_pw);
            secureErase(new_pw);
        }
        else if (choice == 7)
        {
            break;
        }
    }
    return 0;
}