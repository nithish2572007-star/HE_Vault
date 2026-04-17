#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <map>

// Crypto headers
#include <seal/seal.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;
using namespace seal;

// --- Config & File Paths ---
const string PARAMS_FILE = "params.bin";
const string PK_FILE = "public_key.bin";
const string SK_ENC_FILE = "secret_key.enc";
const string DATA_FILE = "data_store.bin";

const int SALT_LEN = 16;
const int IV_LEN = 12;
const int TAG_LEN = 16;
const int KEY_LEN = 32;
const int PBKDF2_ITERS = 100000;

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
        if(!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, SALT_LEN, PBKDF2_ITERS, EVP_sha256(), KEY_LEN, key)) 
        {
            handleErrors();
        }
    }

    static string encryptSK(const string& plaintext_sk, const string& password) 
    {
        unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];
        
        RAND_bytes(salt, SALT_LEN);
        RAND_bytes(iv, IV_LEN);
        deriveKey(password, salt, key);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len;
        int ciphertext_len;
        vector<unsigned char> ciphertext(plaintext_sk.length() + EVP_MAX_BLOCK_LENGTH);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext_sk.data(), plaintext_sk.length());
        ciphertext_len = len;
        
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
        EVP_CIPHER_CTX_free(ctx);

        string out(reinterpret_cast<char*>(salt), SALT_LEN);
        out.append(reinterpret_cast<char*>(iv), IV_LEN);
        out.append(reinterpret_cast<char*>(tag), TAG_LEN);
        out.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
        
        return out;
    }

    static string decryptSK(const string& packaged_data, const string& password) 
    {
        if(packaged_data.length() < SALT_LEN + IV_LEN + TAG_LEN) 
        {
            return ""; 
        }

        unsigned char salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN], key[KEY_LEN];
        memcpy(salt, packaged_data.data(), SALT_LEN);
        memcpy(iv, packaged_data.data() + SALT_LEN, IV_LEN);
        memcpy(tag, packaged_data.data() + SALT_LEN + IV_LEN, TAG_LEN);
        
        deriveKey(password, salt, key);

        const unsigned char* ciphertext = (const unsigned char*)(packaged_data.data() + SALT_LEN + IV_LEN + TAG_LEN);
        int ciphertext_len = packaged_data.length() - (SALT_LEN + IV_LEN + TAG_LEN);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len;
        int plaintext_len;
        vector<unsigned char> plaintext(ciphertext_len);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
        plaintext_len = len;
        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if(ret > 0) 
        {
            plaintext_len += len;
            return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
        } 
        else 
        {
            return ""; 
        }
    }
};

class Vault 
{
private:
    shared_ptr<SEALContext> context_;

    void loadContext() 
    {
        ifstream fs(PARAMS_FILE, ios::binary);
        if(!fs.is_open()) 
        {
            throw runtime_error("[-] Error: Run setup first.");
        }
        EncryptionParameters parms;
        parms.load(fs);
        context_ = make_shared<SEALContext>(parms);
    }

    bool accountExists(const string& target_account, const string& password) 
    {
        ifstream fs_data(DATA_FILE, ios::binary);
        if(!fs_data.is_open() || fs_data.peek() == EOF) 
        {
            return false; 
        }

        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        streamsize size = fs_sk.tellg();
        fs_sk.seekg(0, ios::beg);
        
        string enc_sk_data(size, '\0');
        fs_sk.read(&enc_sk_data[0], size);
        
        string raw_sk = CryptoManager::decryptSK(enc_sk_data, password);
        if(raw_sk.empty()) 
        {
            throw runtime_error("[-] Error: Invalid master password.");
        }

        stringstream sk_ss(raw_sk);
        SecretKey secret_key;
        secret_key.load(*context_, sk_ss);
        
        Decryptor decryptor(*context_, secret_key);
        BatchEncoder batch_encoder(*context_);

        string search_prefix = target_account + "|";

        while(fs_data.peek() != EOF) 
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
                for(uint64_t val : pod_matrix) 
                {
                    if(val == 0) break;
                    decoded_str += static_cast<char>(val);
                }
                
                if(decoded_str.find(search_prefix) == 0) 
                {
                    return true; 
                }
            }
            catch(const exception& e) 
            {
                break; 
            }
        }
        return false;
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

        ofstream fs_data(DATA_FILE, ios::binary | ios::trunc);
        fs_data.close();

        ofstream fs_params(PARAMS_FILE, ios::binary);
        parms.save(fs_params);

        KeyGenerator keygen(*context_);
        SecretKey secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);

        ofstream fs_pk(PK_FILE, ios::binary);
        public_key.save(fs_pk);

        stringstream sk_ss;
        secret_key.save(sk_ss);
        
        string enc_sk = CryptoManager::encryptSK(sk_ss.str(), password);
        ofstream fs_sk(SK_ENC_FILE, ios::binary);
        fs_sk.write(enc_sk.data(), enc_sk.length());

        cout << "[+] Setup complete. Vault reset and new keys generated.\n";
    }

    void store(const string& account_name, const string& credentials, const string& password) 
    {
        loadContext();
        
        if(account_name.find('|') != string::npos) 
        {
            cout << "[-] Error: Account names cannot contain the '|' character.\n";
            return;
        }

        if(accountExists(account_name, password)) 
        {
            cout << "[-] Request Rejected: An account with the name '" << account_name << "' already exists.\n";
            return;
        }

        string formatted_data = account_name + "|" + credentials;

        BatchEncoder batch_encoder(*context_);
        size_t slot_count = batch_encoder.slot_count();
        
        if(formatted_data.length() > slot_count) 
        {
            throw runtime_error("[-] Error: Payload exceeds max vault slot size.");
        }

        vector<uint64_t> pod_matrix(slot_count, 0ULL);
        for(size_t i = 0; i < formatted_data.length() && i < slot_count; ++i) 
        {
            pod_matrix[i] = static_cast<uint64_t>(formatted_data[i]);
        }
        
        Plaintext plain_data;
        batch_encoder.encode(pod_matrix, plain_data);

        ifstream fs_pk(PK_FILE, ios::binary);
        PublicKey public_key;
        public_key.load(*context_, fs_pk);

        Encryptor encryptor(*context_, public_key);
        Ciphertext encrypted_data;
        encryptor.encrypt(plain_data, encrypted_data);

        ofstream fs_data(DATA_FILE, ios::binary | ios::app);
        encrypted_data.save(fs_data);
        
        cout << "[+] Account stored successfully.\n";
    }

    void retrieve(const string& password) 
    {
        loadContext();

        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        if(!fs_sk.is_open()) 
        {
            cout << "[-] Error: Vault does not exist. Run Setup first.\n";
            return;
        }

        streamsize size = fs_sk.tellg();
        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        
        if(fs_sk.read(&enc_sk_data[0], size)) 
        {
            string raw_sk = CryptoManager::decryptSK(enc_sk_data, password);
            if(raw_sk.empty()) 
            {
                cout << "[-] Error: Invalid master password.\n";
                return;
            }

            stringstream sk_ss(raw_sk);
            SecretKey secret_key;
            secret_key.load(*context_, sk_ss);

            Decryptor decryptor(*context_, secret_key);
            BatchEncoder batch_encoder(*context_);

            ifstream fs_data(DATA_FILE, ios::binary);
            if(!fs_data.is_open()) 
            {
                cout << "[-] Vault is empty.\n";
                return;
            }

            map<string, string> decrypted_accounts;

            while(fs_data.peek() != EOF) 
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
                    for(uint64_t val : pod_matrix) 
                    {
                        if(val == 0) break;
                        decoded_str += static_cast<char>(val);
                    }
                    
                    size_t delim_pos = decoded_str.find('|');
                    if(delim_pos != string::npos) 
                    {
                        decrypted_accounts[decoded_str.substr(0, delim_pos)] = decoded_str.substr(delim_pos + 1);
                    } 
                }
                catch(const exception& e) 
                {
                    break; 
                }
            }

            if(decrypted_accounts.empty()) 
            {
                cout << "[-] No formatted accounts found.\n";
                return;
            }

            cout << "\n--- Available Accounts ---\n";
            for(const auto& pair : decrypted_accounts) 
            {
                cout << "- " << pair.first << "\n";
            }
            cout << "--------------------------\n";

            cout << "Enter the name of the account to retrieve its credentials: ";
            string target_account;
            getline(cin, target_account);

            auto it = decrypted_accounts.find(target_account);
            if(it != decrypted_accounts.end()) 
            {
                cout << "\n[+] Credentials for '" << target_account << "': " << it->second << "\n";
            } 
            else 
            {
                cout << "[-] Account '" << target_account << "' not found.\n";
            }
        }
    }

    void changePassword(const string& old_pw, const string& new_pw) 
    {
        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        if(!fs_sk.is_open()) 
        {
            cout << "[-] Error: Vault does not exist.\n";
            return;
        }

        streamsize size = fs_sk.tellg();
        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        fs_sk.read(&enc_sk_data[0], size);
        fs_sk.close();

        string raw_sk = CryptoManager::decryptSK(enc_sk_data, old_pw);
        if(raw_sk.empty()) 
        {
            cout << "[-] Error: Incorrect current password.\n";
            return;
        }

        string new_enc_sk = CryptoManager::encryptSK(raw_sk, new_pw);
        ofstream out_sk(SK_ENC_FILE, ios::binary | ios::trunc);
        out_sk.write(new_enc_sk.data(), new_enc_sk.length());

        cout << "[+] Password updated successfully.\n";
    }
};

int main() 
{
    Vault vault;
    int choice;

    while(true) 
    {
        cout << "\n==============================\n";
        cout << "      SovereignVault CLI      \n";
        cout << "==============================\n";
        cout << "  1. Setup / Factory Reset\n";
        cout << "  2. Add Account\n";
        cout << "  3. Retrieve Credentials\n";
        cout << "  4. Change Master Password\n";
        cout << "  5. Exit\n";
        cout << "==============================\n";
        cout << "> ";
        
        if(!(cin >> choice)) 
        {
            cin.clear();
            cin.ignore(10000, '\n');
            continue;
        }
        
        cin.ignore(10000, '\n');

        if(choice == 1) 
        {
            string pw;
            cout << "Enter new master password: ";
            getline(cin, pw);
            vault.setup(pw);
        }
        else if(choice == 2) 
        {
            string account_name, credentials, master_pw;
            cout << "Enter master password: ";
            getline(cin, master_pw);
            
            cout << "Enter account name: ";
            getline(cin, account_name);
            
            cout << "Enter credentials to store: ";
            getline(cin, credentials);
            
            try 
            { 
                vault.store(account_name, credentials, master_pw); 
            } 
            catch(exception& e) 
            { 
                cout << e.what() << "\n"; 
            }
        }
        else if(choice == 3) 
        {
            string pw;
            cout << "Enter master password: ";
            getline(cin, pw);
            
            try 
            { 
                vault.retrieve(pw); 
            }
            catch(exception& e) 
            { 
                cout << e.what() << "\n"; 
            }
        }
        else if(choice == 4) 
        {
            string old_pw, new_pw;
            cout << "Enter current password: ";
            getline(cin, old_pw);
            cout << "Enter new password: ";
            getline(cin, new_pw);
            
            try 
            { 
                vault.changePassword(old_pw, new_pw); 
            }
            catch(exception& e) 
            { 
                cout << e.what() << "\n"; 
            }
        }
        else if(choice == 5) 
        {
            break;
        }
    }
    return 0;
}