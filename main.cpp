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

// AES/PBKDF2 constants
const int SALT_LEN = 16;
const int IV_LEN = 12;
const int TAG_LEN = 16;
const int KEY_LEN = 32;
const int PBKDF2_ITERS = 100000; // Bump this if running on faster hardware

// Handles the AES-256-GCM wrapping so the HE secret key isn't sitting in plaintext
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

    static string encryptSK(const string& pt_sk, const string& password) 
    {
        unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];
        
        // Generate random salt and IV
        RAND_bytes(salt, SALT_LEN);
        RAND_bytes(iv, IV_LEN);
        deriveKey(password, salt, key);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len;
        int ct_len;
        vector<unsigned char> ciphertext(pt_sk.length() + EVP_MAX_BLOCK_LENGTH);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)pt_sk.data(), pt_sk.length());
        ct_len = len;
        
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ct_len += len;
        
        // Get the GCM auth tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
        EVP_CIPHER_CTX_free(ctx);

        // Pack it all up: [Salt][IV][Tag][Ciphertext]
        string out(reinterpret_cast<char*>(salt), SALT_LEN);
        out.append(reinterpret_cast<char*>(iv), IV_LEN);
        out.append(reinterpret_cast<char*>(tag), TAG_LEN);
        out.append(reinterpret_cast<char*>(ciphertext.data()), ct_len);
        
        return out;
    }

    static string decryptSK(const string& packaged_data, const string& password) 
    {
        if(packaged_data.length() < SALT_LEN + IV_LEN + TAG_LEN) 
        {
            return ""; // Data is corrupted or too short
        }

        unsigned char salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN], key[KEY_LEN];
        memcpy(salt, packaged_data.data(), SALT_LEN);
        memcpy(iv, packaged_data.data() + SALT_LEN, IV_LEN);
        memcpy(tag, packaged_data.data() + SALT_LEN + IV_LEN, TAG_LEN);
        
        deriveKey(password, salt, key);

        const unsigned char* ciphertext = (const unsigned char*)(packaged_data.data() + SALT_LEN + IV_LEN + TAG_LEN);
        int ct_len = packaged_data.length() - (SALT_LEN + IV_LEN + TAG_LEN);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len;
        int pt_len;
        vector<unsigned char> plaintext(ct_len);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ct_len);
        pt_len = len;
        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if(ret > 0) 
        {
            pt_len += len;
            return string(reinterpret_cast<char*>(plaintext.data()), pt_len);
        } 
        else 
        {
            return ""; // Auth tag failed (wrong password)
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
            throw runtime_error("Error: Vault not initialized. Run setup first.");
        }
        EncryptionParameters parms;
        parms.load(fs);
        context_ = make_shared<SEALContext>(parms);
    }

    bool accountExists(const string& target_acc, const string& master_pass) 
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
        
        string raw_sk = CryptoManager::decryptSK(enc_sk_data, master_pass);
        if(raw_sk.empty()) 
        {
            throw runtime_error("Auth failed. Incorrect master password.");
        }

        stringstream sk_ss(raw_sk);
        SecretKey secret_key;
        secret_key.load(*context_, sk_ss);
        
        Decryptor decryptor(*context_, secret_key);
        BatchEncoder batch_encoder(*context_);

        string search_prefix = target_acc + "|";

        // TODO: This is an O(n) linear scan. Gets slow with a lot of accounts.
        // Need to refactor data_store.bin into a proper Binary Search Tree structure later.
        while(fs_data.peek() != EOF) 
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
        return false;
    }

public:
    void setup(const string& master_pass) 
    {
        cout << "[*] Generating SEAL context (poly_modulus_degree = 4096)...\n";
        
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 4096;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

        context_ = make_shared<SEALContext>(parms);

        // Crucial: Truncate the file to prevent orphaned ciphertexts.
        // If we don't do this, old data becomes permanently undecryptable junk.
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
        
        string enc_sk = CryptoManager::encryptSK(sk_ss.str(), master_pass);
        ofstream fs_sk(SK_ENC_FILE, ios::binary);
        fs_sk.write(enc_sk.data(), enc_sk.length());

        cout << "[+] Setup complete. Previous vault data erased.\n";
    }

    void store(const string& target_acc, const string& creds, const string& master_pass) 
    {
        loadContext();
        
        cout << "[*] Checking for duplicates...\n";
        if(accountExists(target_acc, master_pass)) 
        {
            cout << "[-] Rejected: Account '" << target_acc << "' already exists.\n";
            return;
        }

        string formatted_data = target_acc + "|" + creds;

        BatchEncoder batch_encoder(*context_);
        size_t slot_count = batch_encoder.slot_count();
        
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

        // Append raw ciphertext to disk
        ofstream fs_data(DATA_FILE, ios::binary | ios::app);
        encrypted_data.save(fs_data);
        
        cout << "[+] Saved.\n";
    }

    void retrieve(const string& master_pass) 
    {
        loadContext();

        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        streamsize size = fs_sk.tellg();
        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        
        if(fs_sk.read(&enc_sk_data[0], size)) 
        {
            string raw_sk = CryptoManager::decryptSK(enc_sk_data, master_pass);
            if(raw_sk.empty()) 
            {
                cout << "[-] Auth failed. Wrong password.\n";
                return;
            }

            cout << "[*] Decrypting vault...\n";
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

            map<string, string> acc_map;

            while(fs_data.peek() != EOF) 
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
                    acc_map[decoded_str.substr(0, delim_pos)] = decoded_str.substr(delim_pos + 1);
                } 
            }

            if(acc_map.empty()) 
            {
                cout << "[-] No formatted accounts found in data store.\n";
                return;
            }

            cout << "\n--- Accounts ---\n";
            for(const auto& pair : acc_map) 
            {
                cout << " > " << pair.first << "\n";
            }
            cout << "----------------\n\n";

            cout << "Enter account name to fetch creds: ";
            string target_acc;
            cin.ignore(); 
            getline(cin, target_acc);

            auto it = acc_map.find(target_acc);
            if(it != acc_map.end()) 
            {
                cout << "\n[+] " << target_acc << " -> " << it->second << "\n";
            } 
            else 
            {
                cout << "[-] Account not found.\n";
            }
        }
    }

    void changePassword(const string& old_pass, const string& new_pass) 
    {
        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        streamsize size = fs_sk.tellg();
        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        fs_sk.read(&enc_sk_data[0], size);
        fs_sk.close();

        string raw_sk = CryptoManager::decryptSK(enc_sk_data, old_pass);
        if(raw_sk.empty()) 
        {
            cout << "[-] Auth failed. Wrong current password.\n";
            return;
        }

        string new_enc_sk = CryptoManager::encryptSK(raw_sk, new_pass);
        ofstream out_sk(SK_ENC_FILE, ios::binary | ios::trunc);
        out_sk.write(new_enc_sk.data(), new_enc_sk.length());

        cout << "[+] Master password updated. Data payload untouched.\n";
    }
};

void printMenu() 
{
    cout << "\n==============================\n";
    cout << "       SovereignVault CLI     \n";
    cout << "==============================\n";
    cout << " 1. Setup / Factory Reset\n";
    cout << " 2. Add Account\n";
    cout << " 3. Retrieve Credentials\n";
    cout << " 4. Change Master Password\n";
    cout << " 5. Exit\n";
    cout << "==============================\n";
    cout << "> ";
}

int main() 
{
    Vault vault;
    int choice;

    while(true) 
    {
        printMenu();
        
        // Handle non-integer inputs gracefully so we don't infinite loop
        if(!(cin >> choice)) 
        {
            cin.clear();
            cin.ignore(10000, '\n');
            cout << "[-] Invalid input.\n";
            continue;
        }

        if(choice == 1) 
        {
            string pass;
            cout << "Enter new master pass: ";
            cin >> pass;
            vault.setup(pass);
        }
        else if(choice == 2) 
        {
            string target_acc, creds, master_pass;
            cout << "Enter master pass (to unlock & check for dupes): ";
            cin >> master_pass;
            
            cout << "Account name : ";
            cin.ignore();
            getline(cin, target_acc);
            
            cout << "Credentials: ";
            getline(cin, creds);
            
            try 
            { 
                vault.store(target_acc, creds, master_pass); 
            } 
            catch(exception& e) 
            { 
                cout << e.what() << "\n"; 
            }
        }
        else if(choice == 3) 
        {
            string pass;
            cout << "Enter master pass: ";
            cin >> pass;
            
            try 
            { 
                vault.retrieve(pass); 
            }
            catch(exception& e) 
            { 
                cout << e.what() << "\n"; 
            }
        }
        else if(choice == 4) 
        {
            string old_pass, new_pass;
            cout << "Current pass: ";
            cin >> old_pass;
            cout << "New pass: ";
            cin >> new_pass;
            
            try 
            { 
                vault.changePassword(old_pass, new_pass); 
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
        else 
        {
            cout << "[-] Invalid choice.\n";
        }
    }
    return 0;
}