#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <seal/seal.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;
using namespace seal;

const string PARAMS_FILE = "params.bin";
const string PK_FILE = "public_key.bin";
const string SK_ENC_FILE = "secret_key.enc";
const string DATA_FILE = "data_store.bin";

const int SALT_LEN = 16;
const int IV_LEN = 12;
const int TAG_LEN = 16;
const int KEY_LEN = 32;
const int PBKDF2_ITERS = 100000;

class CryptoManager {
public:
    static void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }

    static void deriveKey(const string& password, const unsigned char* salt, unsigned char* key) {
        if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, SALT_LEN, PBKDF2_ITERS, EVP_sha256(), KEY_LEN, key)) {
            handleErrors();
        }
    }

    static string encryptSK(const string& plaintext_sk, const string& password) {
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

    static string decryptSK(const string& packaged_data, const string& password) {
        if (packaged_data.length() < SALT_LEN + IV_LEN + TAG_LEN) return "";

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

        if (ret > 0) {
            plaintext_len += len;
            return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
        } else {
            return ""; 
        }
    }
};

class Vault {
private:
    shared_ptr<SEALContext> context_;

    void loadContext() {
        ifstream fs(PARAMS_FILE, ios::binary);
        if (!fs.is_open()) throw runtime_error("Run setup first.");
        EncryptionParameters parms;
        parms.load(fs);
        context_ = make_shared<SEALContext>(parms);
    }

public:
    void setup(const string& password) {
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 4096;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

        context_ = make_shared<SEALContext>(parms);

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

        cout << "[+] Setup complete. Keys generated and FHE context saved.\n";
    }

    void store(const string& data) {
        loadContext();
        BatchEncoder batch_encoder(*context_);
        size_t slot_count = batch_encoder.slot_count();

        vector<uint64_t> pod_matrix(slot_count, 0ULL);
        for(size_t i = 0; i < data.length() && i < slot_count; ++i) {
            pod_matrix[i] = static_cast<uint64_t>(data[i]);
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

        cout << "[+] Data mathematically encoded, encrypted, and written to disk.\n";
    }

    void retrieve(const string& password) {
        loadContext();

        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        streamsize size = fs_sk.tellg();
        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        if (fs_sk.read(&enc_sk_data[0], size)) {
            string raw_sk = CryptoManager::decryptSK(enc_sk_data, password);
            if(raw_sk.empty()) {
                cout << "[-] Error: Invalid password or corrupted secret key.\n";
                return;
            }

            stringstream sk_ss(raw_sk);
            SecretKey secret_key;
            secret_key.load(*context_, sk_ss);

            Decryptor decryptor(*context_, secret_key);
            BatchEncoder batch_encoder(*context_);

            ifstream fs_data(DATA_FILE, ios::binary);
            if (!fs_data.is_open()) {
                cout << "[-] No data file found.\n";
                return;
            }

            cout << "\n--- Decrypted Vault Contents ---\n";
            while(fs_data.peek() != EOF) {
                Ciphertext encrypted_data;
                encrypted_data.load(*context_, fs_data);

                Plaintext plain_data;
                decryptor.decrypt(encrypted_data, plain_data);

                vector<uint64_t> pod_matrix;
                batch_encoder.decode(plain_data, pod_matrix);

                string decoded_str;
                for(uint64_t val : pod_matrix) {
                    if (val == 0) break;
                    decoded_str += static_cast<char>(val);
                }
                cout << "- " << decoded_str << "\n";
            }
            cout << "--------------------------------\n";
        }
    }

    void changePassword(const string& old_pw, const string& new_pw) {
        ifstream fs_sk(SK_ENC_FILE, ios::binary | ios::ate);
        streamsize size = fs_sk.tellg();
        fs_sk.seekg(0, ios::beg);
        string enc_sk_data(size, '\0');
        fs_sk.read(&enc_sk_data[0], size);
        fs_sk.close();

        string raw_sk = CryptoManager::decryptSK(enc_sk_data, old_pw);
        if(raw_sk.empty()) {
            cout << "[-] Error: Incorrect current password.\n";
            return;
        }

        string new_enc_sk = CryptoManager::encryptSK(raw_sk, new_pw);
        ofstream out_sk(SK_ENC_FILE, ios::binary | ios::trunc);
        out_sk.write(new_enc_sk.data(), new_enc_sk.length());

        cout << "[+] Password changed successfully. Data payload untouched.\n";
    }
};

int main() {
    Vault vault;
    int choice;

    while (true) {
        cout << "\n=== FHE Data Vault ===\n";
        cout << "1. Setup / Initialize (Destroys existing keys)\n";
        cout << "2. Store Data Entry\n";
        cout << "3. Retrieve Data\n";
        cout << "4. Change Access Password\n";
        cout << "5. Exit\n";
        cout << "Select option: ";
        if (!(cin >> choice)) break;

        if (choice == 1) {
            string pw;
            cout << "Enter new master password: ";
            cin >> pw;
            vault.setup(pw);
        }
        else if (choice == 2) {
            string data;
            cout << "Enter string data to encrypt: ";
            cin.ignore();
            getline(cin, data);
            try { vault.store(data); }
            catch (exception& e) { cout << e.what() << "\n"; }
        }
        else if (choice == 3) {
            string pw;
            cout << "Enter password: ";
            cin >> pw;
            try { vault.retrieve(pw); }
            catch (exception& e) { cout << e.what() << "\n"; }
        }
        else if (choice == 4) {
            string old_pw, new_pw;
            cout << "Enter OLD password: ";
            cin >> old_pw;
            cout << "Enter NEW password: ";
            cin >> new_pw;
            try { vault.changePassword(old_pw, new_pw); }
            catch (exception& e) { cout << e.what() << "\n"; }
        }
        else if (choice == 5) {
            break;
        }
    }
    return 0;
}
