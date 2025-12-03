#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <random>
#include <iomanip>
#include <ctime>
#include <limits>

struct User {
    std::string username;
    std::string salt;
    std::string passwordHash;
    int failedAttempts;
    bool locked;
};

const std::string USER_DB_FILE = "users.db";
const std::string LOG_FILE = "auth.log";
const int MAX_FAILED_ATTEMPTS = 3;
const int MAX_USERNAME_LENGTH = 32;
const int MAX_PASSWORD_LENGTH = 64;
const int OTP_VALID_SECONDS = 60;

std::string currentTimeString() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm *tmPtr = std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(tmPtr, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void logEvent(const std::string &username, const std::string &event) {
    std::ofstream log(LOG_FILE, std::ios::app);
    if (!log.is_open()) return;
    log << "[" << currentTimeString() << "] "
        << "user=" << username << " "
        << event << "\n";
}

std::string toHex(size_t value) {
    std::ostringstream oss;
    oss << std::hex << value;
    return oss.str();
}

std::string hashPassword(const std::string &salt, const std::string &password) {
    std::hash<std::string> hasher;
    size_t h = hasher(salt + password);
    return toHex(h);
}

std::string generateSalt(size_t length = 16) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 15);
    const char *hexChars = "0123456789abcdef";

    std::string s;
    s.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        s.push_back(hexChars[dist(gen)]);
    }
    return s;
}

int generateOTP() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 999999);
    return dist(gen);
}

std::vector<User> loadUsers() {
    std::vector<User> users;
    std::ifstream file(USER_DB_FILE);
    if (!file.is_open()) return users;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string part;
        User u;
        std::getline(ss, u.username, '|');
        std::getline(ss, u.salt, '|');
        std::getline(ss, u.passwordHash, '|');
        std::getline(ss, part, '|');
        u.failedAttempts = std::stoi(part);
        std::getline(ss, part, '|');
        u.locked = (part == "1");
        users.push_back(u);
    }
    return users;
}

void saveUsers(const std::vector<User> &users) {
    std::ofstream file(USER_DB_FILE, std::ios::trunc);
    if (!file.is_open()) return;

    for (const auto &u : users) {
        file << u.username << "|"
             << u.salt << "|"
             << u.passwordHash << "|"
             << u.failedAttempts << "|"
             << (u.locked ? "1" : "0")
             << "\n";
    }
}

int findUserIndex(const std::vector<User> &users, const std::string &username) {
    for (size_t i = 0; i < users.size(); ++i) {
        if (users[i].username == username) return static_cast<int>(i);
    }
    return -1;
}

std::string safeInput(const std::string &prompt, int maxLen) {
    std::string input;
    while (true) {
        std::cout << prompt;
        std::getline(std::cin, input);
        if (!std::cin) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        if ((int)input.size() > maxLen) {
            std::cout << "Input too long. Max length is " << maxLen << ". Try again.\n";
            continue;
        }
        if (input.find('|') != std::string::npos) {
            std::cout << "Character '|' is not allowed. Try again.\n";
            continue;
        }
        break;
    }
    return input;
}

void registerUser() {
    auto users = loadUsers();
    std::string username = safeInput("Enter new username: ", MAX_USERNAME_LENGTH);

    if (findUserIndex(users, username) != -1) {
        std::cout << "Username already exists.\n";
        return;
    }

    std::string password = safeInput("Enter new password: ", MAX_PASSWORD_LENGTH);
    if (password.size() < 6) {
        std::cout << "Password must be at least 6 characters.\n";
        return;
    }

    std::string salt = generateSalt();
    std::string hash = hashPassword(salt, password);

    User u;
    u.username = username;
    u.salt = salt;
    u.passwordHash = hash;
    u.failedAttempts = 0;
    u.locked = false;

    users.push_back(u);
    saveUsers(users);

    logEvent(username, "registration_success");
    std::cout << "User registered successfully.\n";
}

void loginUser() {
    auto users = loadUsers();
    std::string username = safeInput("Username: ", MAX_USERNAME_LENGTH);

    int idx = findUserIndex(users, username);
    if (idx == -1) {
        logEvent(username, "login_failed_user_not_found");
        std::cout << "Invalid credentials.\n";
        return;
    }

    User &u = users[idx];

    if (u.locked) {
        logEvent(username, "login_denied_account_locked");
        std::cout << "Account is locked due to too many failed attempts.\n";
        return;
    }

    std::string password = safeInput("Password: ", MAX_PASSWORD_LENGTH);
    std::string hash = hashPassword(u.salt, password);

    if (hash != u.passwordHash) {
        u.failedAttempts++;
        if (u.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            u.locked = true;
            logEvent(username, "account_locked_due_to_failed_password_attempts");
            std::cout << "Too many failed attempts. Account locked.\n";
        } else {
            logEvent(username, "login_failed_wrong_password");
            std::cout << "Invalid credentials. Attempts left: "
                      << (MAX_FAILED_ATTEMPTS - u.failedAttempts) << "\n";
        }
        saveUsers(users);
        return;
    }

    u.failedAttempts = 0;
    saveUsers(users);

    int otp = generateOTP();
    auto otpGenTime = std::chrono::steady_clock::now();

    std::cout << "Primary authentication successful.\n";
    std::cout << "Your OTP (for demo): " << std::setw(6) << std::setfill('0') << otp << "\n";

    std::string otpInputStr = safeInput("Enter OTP: ", 6);
    int otpInput = -1;
    try {
        otpInput = std::stoi(otpInputStr);
    } catch (...) {
        otpInput = -1;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - otpGenTime).count();

    if (elapsed > OTP_VALID_SECONDS) {
        logEvent(username, "login_failed_otp_expired");
        std::cout << "OTP expired. Login denied.\n";
        return;
    }

    if (otpInput != otp) {
        logEvent(username, "login_failed_wrong_otp");
        std::cout << "Invalid OTP. Login denied.\n";
        return;
    }

    logEvent(username, "login_success");
    std::cout << "Login successful. Access granted.\n";
}

int main() {
    while (true) {
        std::cout << "\n=== Secure Authentication Module ===\n";
        std::cout << "1. Register\n";
        std::cout << "2. Login\n";
        std::cout << "3. Exit\n";
        std::cout << "Choose option: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == 1) {
            registerUser();
        } else if (choice == 2) {
            loginUser();
        } else if (choice == 3) {
            std::cout << "Exiting.\n";
            break;
        } else {
            std::cout << "Invalid option.\n";
        }
    }
    return 0;
}
