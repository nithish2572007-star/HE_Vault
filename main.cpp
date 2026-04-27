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

const size_t MAX_INPUT_LEN  = 1024;
const string TEMP_DATA_FILE = "data_store.bin.tmp";

// no arbitrary cap that silently leaves bytes in the stream buffer.
static constexpr streamsize IGNORE_MAX = numeric_limits<streamsize>::max();

// RAII wrapper — EVP_CIPHER_CTX is always freed even if an exception propagates.
struct CtxGuard
{
    EVP_CIPHER_CTX* ctx;
    explicit CtxGuard() : ctx(EVP_CIPHER_CTX_new()) {}
    ~CtxGuard() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
    CtxGuard(const CtxGuard&)            = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
};

// Securely erase sensitive string data from heap memory before it goes out of scope.
static void secureErase(string& s)
{
    if (!s.empty())
        OPENSSL_cleanse(&s[0], s.size());
}

// clears it, so plaintext credentials do not linger on the heap after use.
static void secureEraseMap(map<string, string>& m)
{
    for (auto& kv : m)
    {
        secureErase(kv.second);   // zero the credential
        // key (account name) is not secret, but erase it anyway for hygiene
        secureErase(const_cast<string&>(kv.first));
    }
    m.clear();
}

// Read one line from stdin, capped at MAX_INPUT_LEN bytes.
// Returns false on EOF or if the input exceeded the limit (out is cleared).
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
        if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.length(),
                                salt, SALT_LEN, PBKDF2_ITERS,
                                EVP_sha256(), KEY_LEN, key))
        {
            handleErrors();
        }
    }

    static string encryptSK(const string& plaintext_sk, const string& password)
    {
        unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];

        if (RAND_bytes(salt, SALT_LEN) != 1) handleErrors();
        if (RAND_bytes(iv,   IV_LEN)   != 1) handleErrors();
        deriveKey(password, salt, key);

        CtxGuard g;
        if (!g.ctx) handleErrors();

        EVP_CIPHER_CTX* ctx = g.ctx;
        int len = 0, ciphertext_len = 0;
        vector<unsigned char> ciphertext(plaintext_sk.length() + EVP_MAX_BLOCK_LENGTH);

        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
        if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))                  handleErrors();
        if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                               (const unsigned char*)plaintext_sk.data(),
                               (int)plaintext_sk.length()))                 handleErrors();
        ciphertext_len = len;

        if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))      handleErrors();
        ciphertext_len += len;

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, (void*)tag)) handleErrors();

        string out(reinterpret_cast<char*>(salt),              SALT_LEN);
        out.append(reinterpret_cast<char*>(iv),                IV_LEN);
        out.append(reinterpret_cast<char*>(tag),               TAG_LEN);
        out.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);

        // Zero sensitive key material before returning.
        OPENSSL_cleanse(key, KEY_LEN);
        // the serialised secret key — not the output blob, but the staging buffer).
        OPENSSL_cleanse(ciphertext.data(), ciphertext.size());
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
        if (!g.ctx)
        {
            OPENSSL_cleanse(key, KEY_LEN);
            return "";
        }

        EVP_CIPHER_CTX* ctx = g.ctx;
        int len = 0, plaintext_len = 0;
        vector<unsigned char> plaintext(ciphertext_len);

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
            !EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)                  ||
            !EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len))
        {
            OPENSSL_cleanse(key, KEY_LEN);
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            return "";
        }
        plaintext_len = len;

        // SET_TAG must be called before DecryptFinal.
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag))
        {
            OPENSSL_cleanse(key, KEY_LEN);
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            return "";
        }

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len);
        OPENSSL_cleanse(key, KEY_LEN);

        if (ret > 0)
        {
            plaintext_len += len;
            string result(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
            // string holds its own copy.
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            return result;
        }
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
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

        if (size <= 0)
            throw runtime_error("[-] Error: Could not read secret key file.");

        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        fs_sk.read(&enc_sk_data[0], size);
        fs_sk.close();

        string raw_sk = CryptoManager::decryptSK(enc_sk_data, password);

        secureErase(enc_sk_data);

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

        secureErase(raw_sk);

        string sk_ss_buf = sk_ss.str();
        secureErase(sk_ss_buf);
        sk_ss.str(sk_ss_buf);

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

                // plaintext credential data and must not linger on the heap.
                secureErase(decoded_str);
                OPENSSL_cleanse(pod_matrix.data(), pod_matrix.size() * sizeof(uint64_t));
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
        // Atomic write: write to temp file first, then rename over DATA_FILE.
        // This eliminates data loss on crash mid-write.

        if (accounts.empty())
        {
            {
                ofstream tmp(TEMP_DATA_FILE, ios::binary | ios::trunc);
                if (!tmp.is_open())
                    throw runtime_error("[-] Fatal: could not create temp vault file.");
            }
            error_code ec;
            filesystem::rename(TEMP_DATA_FILE, DATA_FILE, ec);
            if (ec)
                throw runtime_error("[-] Fatal: could not atomically replace vault file: " + ec.message());
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
            {
                // plaintext credential is not left on the heap when we unwind.
                secureErase(formatted_data);
                throw runtime_error("[-] Error: Payload exceeds max vault slot size.");
            }

            vector<uint64_t> pod_matrix(slot_count, 0ULL);
            for (size_t i = 0; i < formatted_data.length() && i < slot_count; ++i)
                pod_matrix[i] = static_cast<uint64_t>(formatted_data[i]);

            // encoding so plaintext credentials don't linger on the heap.
            secureErase(formatted_data);

            Plaintext plain_data;
            batch_encoder.encode(pod_matrix, plain_data);
            OPENSSL_cleanse(pod_matrix.data(), pod_matrix.size() * sizeof(uint64_t));

            Ciphertext encrypted_data;
            encryptor.encrypt(plain_data, encrypted_data);

            encrypted_data.save(tmp);

            // a partial failure is detected immediately rather than at close().
            if (!tmp)
            {
                tmp.close();
                filesystem::remove(TEMP_DATA_FILE);
                throw runtime_error("[-] Fatal: write error while saving vault record.");
            }
        }

        tmp.close();

        // errors until flush; if the close failed, the temp file is incomplete.
        if (!tmp)
        {
            filesystem::remove(TEMP_DATA_FILE);
            throw runtime_error("[-] Fatal: write error on vault temp file (flush failed).");
        }

        // Atomic swap.
        error_code ec;
        filesystem::rename(TEMP_DATA_FILE, DATA_FILE, ec);
        if (ec)
        {
            filesystem::remove(TEMP_DATA_FILE);
            throw runtime_error("[-] Fatal: could not atomically replace vault file: " + ec.message());
        }
    }

    // Shared input validation for account names and credentials.
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

        // Reset data store atomically.
        {
            ofstream tmp(TEMP_DATA_FILE, ios::binary | ios::trunc);
            if (!tmp.is_open())
                throw runtime_error("[-] Fatal: could not create temp vault file.");
        }
        error_code ec;
        filesystem::rename(TEMP_DATA_FILE, DATA_FILE, ec);
        if (ec)
            throw runtime_error("[-] Fatal: could not initialise data file: " + ec.message());

        // files so a partial write during setup never leaves them corrupted.
        const string TEMP_PARAMS_FILE = "params.bin.tmp";
        ofstream fs_params(TEMP_PARAMS_FILE, ios::binary | ios::trunc);
        if (!fs_params.is_open())
            throw runtime_error("[-] Fatal: could not write params file.");
        parms.save(fs_params);
        if (!fs_params)
        {
            fs_params.close();
            filesystem::remove(TEMP_PARAMS_FILE);
            throw runtime_error("[-] Fatal: write error on params file.");
        }
        fs_params.close();
        filesystem::rename(TEMP_PARAMS_FILE, PARAMS_FILE, ec);
        if (ec)
        {
            filesystem::remove(TEMP_PARAMS_FILE);
            throw runtime_error("[-] Fatal: could not atomically replace params file: " + ec.message());
        }

        KeyGenerator keygen(*context_);
        SecretKey    secret_key = keygen.secret_key();
        PublicKey    public_key;
        keygen.create_public_key(public_key);

        const string TEMP_PK_FILE = "public_key.bin.tmp";
        ofstream fs_pk(TEMP_PK_FILE, ios::binary | ios::trunc);
        if (!fs_pk.is_open())
            throw runtime_error("[-] Fatal: could not write public key file.");
        public_key.save(fs_pk);
        if (!fs_pk)
        {
            fs_pk.close();
            filesystem::remove(TEMP_PK_FILE);
            throw runtime_error("[-] Fatal: write error on public key file.");
        }
        fs_pk.close();
        filesystem::rename(TEMP_PK_FILE, PK_FILE, ec);
        if (ec)
        {
            filesystem::remove(TEMP_PK_FILE);
            throw runtime_error("[-] Fatal: could not atomically replace public key file: " + ec.message());
        }

        stringstream sk_ss;
        secret_key.save(sk_ss);

        string sk_plain = sk_ss.str();
        string enc_sk   = CryptoManager::encryptSK(sk_plain, password);
        secureErase(sk_plain);

        ofstream fs_sk(SK_ENC_FILE, ios::binary | ios::trunc);
        if (!fs_sk.is_open())
            throw runtime_error("[-] Fatal: could not write secret key file.");
        fs_sk.write(enc_sk.data(), (streamsize)enc_sk.length());
        if (!fs_sk)
            throw runtime_error("[-] Fatal: write error on secret key file.");
        fs_sk.close();

        cout << "[+] Setup complete. Vault reset and new keys generated.\n";
    }

    void store(const string& account_name, const string& credentials, const string& password)
    {
        loadContext();

        if (!validateField(account_name, "Account names")) return;
        if (!validateField(credentials,  "Credentials"))   return;

        map<string, string> accounts = loadAllAccounts(password);

        if (accounts.find(account_name) != accounts.end())
        {
            cout << "[-] An account with the name '" << account_name << "' already exists.\n";
            cout << "Would you like to update it with these new credentials? (y/n): ";

            string response;
            if (!safeGetline(response))
            {
                secureEraseMap(accounts);
                return;
            }

            if (response == "y" || response == "Y")
            {
                accounts[account_name] = credentials;
                rewriteVault(accounts);
                // credentials) after every rewriteVault call.
                secureEraseMap(accounts);
                cout << "[+] Account '" << account_name << "' updated successfully.\n";
            }
            else
            {
                secureEraseMap(accounts);
                cout << "[-] Add operation cancelled.\n";
            }
            return;
        }

        accounts[account_name] = credentials;
        rewriteVault(accounts);
        secureEraseMap(accounts);

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

        if (!safeGetline(target_account))
        {
            secureEraseMap(decrypted_accounts);
            return;
        }

        auto it = decrypted_accounts.find(target_account);
        if (it != decrypted_accounts.end())
        {
            cout << "\n[+] Credentials for '" << target_account << "': " << it->second << "\n";

            cout << "Press Enter to clear credentials from screen...";

            string dummy;
            safeGetline(dummy);

            // Move up two lines and erase them (ANSI-compatible terminals).
            cout << "\033[1A\033[2K\033[1A\033[2K" << flush;
        }
        else
        {
            cout << "[-] Account '" << target_account << "' not found.\n";
        }

        // are done displaying — they must not linger on the heap.
        secureEraseMap(decrypted_accounts);
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

        if (!safeGetline(account_name))
        {
            secureEraseMap(accounts);
            return;
        }

        if (!validateField(account_name, "Account name"))
        {
            secureEraseMap(accounts);
            return;
        }

        if (accounts.find(account_name) == accounts.end())
        {
            secureEraseMap(accounts);
            cout << "[-] Error: Account '" << account_name << "' not found.\n";
            return;
        }

        cout << "Enter new credentials: ";
        string new_credentials;
        if (!safeGetline(new_credentials))
        {
            secureEraseMap(accounts);
            return;
        }

        if (!validateField(new_credentials, "Credentials"))
        {
            secureErase(new_credentials);
            secureEraseMap(accounts);
            return;
        }

        accounts[account_name] = new_credentials;
        secureErase(new_credentials);
        rewriteVault(accounts);
        secureEraseMap(accounts);

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

        if (!safeGetline(account_name))
        {
            secureEraseMap(accounts);
            return;
        }

        if (!validateField(account_name, "Account name"))
        {
            secureEraseMap(accounts);
            return;
        }

        if (accounts.find(account_name) == accounts.end())
        {
            secureEraseMap(accounts);
            cout << "[-] Error: Account '" << account_name << "' not found.\n";
            return;
        }

        accounts.erase(account_name);
        rewriteVault(accounts);
        secureEraseMap(accounts);

        cout << "[+] Account '" << account_name << "' deleted successfully.\n";
    }

    void changePassword(const string& old_pw, const string& new_pw)
    {
        string raw_sk = getRawSecretKey(old_pw);

        string new_enc_sk = CryptoManager::encryptSK(raw_sk, new_pw);
        secureErase(raw_sk);

        const string TEMP_SK_FILE = "secret_key.enc.tmp";

        ofstream out_sk(TEMP_SK_FILE, ios::binary | ios::trunc);
        if (!out_sk.is_open())
            throw runtime_error("[-] Fatal: could not open temp SK file for writing.");

        out_sk.write(new_enc_sk.data(), (streamsize)new_enc_sk.length());
        if (!out_sk)
        {
            out_sk.close();
            filesystem::remove(TEMP_SK_FILE);
            throw runtime_error("[-] Fatal: write error on temp SK file.");
        }
        out_sk.close();

        // data is only flushed on close(), so a silent write failure can surface
        // here.  Without this check, a partially-written temp file could be
        // renamed over the real SK file, locking the user out of their vault.
        if (!out_sk)
        {
            filesystem::remove(TEMP_SK_FILE);
            throw runtime_error("[-] Fatal: write error on temp SK file (flush failed).");
        }

        error_code ec;
        filesystem::rename(TEMP_SK_FILE, SK_ENC_FILE, ec);
        if (ec)
        {
            filesystem::remove(TEMP_SK_FILE);
            throw runtime_error("[-] Fatal: could not atomically replace SK file: " + ec.message());
        }

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
        cout << "      HE Vault CLI      \n";
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
            cin.ignore(IGNORE_MAX, '\n');
            continue;
        }
        cin.ignore(IGNORE_MAX, '\n');

        if (choice == 1)
        {
            cout << "WARNING: This will permanently erase all stored accounts and regenerate keys.\n";

            cout << "Type YES to confirm: ";
            string confirm;
            if (!safeGetline(confirm) || confirm != "YES" )
            {
                cout << "[-] Reset cancelled.\n";
                continue;
            }

            string pw, pw_confirm;
            while (true)
            {
                cout << "Enter new master password: ";
                if (!safeGetline(pw))
                {
                    pw.clear();
                    break;
                }
                if (pw.empty())
                {
                    cout << "[-] Error: Master password cannot be empty.\n";
                    continue;
                }

                cout << "Confirm master password: ";
                if (!safeGetline(pw_confirm))
                {
                    secureErase(pw);
                    pw.clear();
                    break;
                }
                if (pw == pw_confirm) break;

                cout << "[-] Passwords do not match. Try again.\n";
                secureErase(pw);
                secureErase(pw_confirm);
            }
            secureErase(pw_confirm);

            if (pw.empty())
            {
                cout << "[-] Setup cancelled.\n";
                continue;
            }

            try { vault.setup(pw); }
            catch (const exception& e) { cout << e.what() << "\n"; }

            secureErase(pw);
        }
        else if (choice == 2)
        {
            string account_name, credentials, master_pw;

            cout << "Enter master password: ";
            if (!safeGetline(master_pw)) continue;

            cout << "Enter account name: ";
            if (!safeGetline(account_name))
            {
                secureErase(master_pw);
                continue;
            }

            cout << "Enter credentials to store: ";
            if (!safeGetline(credentials))
            {
                secureErase(master_pw);
                secureErase(account_name);
                continue;
            }

            try { vault.store(account_name, credentials, master_pw); }
            catch (const exception& e) { cout << e.what() << "\n"; }

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
            catch (const exception& e) { cout << e.what() << "\n"; }

            secureErase(pw);
        }
        else if (choice == 4)
        {
            string master_pw;
            cout << "Enter master password: ";
            if (!safeGetline(master_pw)) continue;

            try { vault.updateAccount(master_pw); }
            catch (const exception& e) { cout << e.what() << "\n"; }

            secureErase(master_pw);
        }
        else if (choice == 5)
        {
            string master_pw;
            cout << "Enter master password: ";
            if (!safeGetline(master_pw)) continue;

            try { vault.deleteAccount(master_pw); }
            catch (const exception& e) { cout << e.what() << "\n"; }

            secureErase(master_pw);
        }
        else if (choice == 6)
        {
            string old_pw, new_pw, new_pw_confirm;

            cout << "Enter current password: ";
            if (!safeGetline(old_pw)) continue;

            while (true)
            {
                cout << "Enter new password: ";
                if (!safeGetline(new_pw))
                {
                    new_pw.clear();
                    break;
                }
                if (new_pw.empty())
                {
                    cout << "[-] Error: New password cannot be empty.\n";
                    continue;
                }

                // old one so that "change password" always results in a
                // material change to the vault's key-derivation input.
                if (new_pw == old_pw)
                {
                    cout << "[-] Error: New password must differ from the current password.\n";
                    secureErase(new_pw);
                    continue;
                }

                cout << "Confirm new password: ";
                if (!safeGetline(new_pw_confirm))
                {
                    secureErase(new_pw);
                    new_pw.clear();
                    break;
                }
                if (new_pw == new_pw_confirm) break;

                cout << "[-] Passwords do not match. Try again.\n";
                secureErase(new_pw);
                secureErase(new_pw_confirm);
            }
            secureErase(new_pw_confirm);

            if (!new_pw.empty())
            {
                try { vault.changePassword(old_pw, new_pw); }
                catch (const exception& e) { cout << e.what() << "\n"; }
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