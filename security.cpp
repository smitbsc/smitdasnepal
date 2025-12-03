#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_INPUT 256
#define MAX_SAFE_PAYLOAD 128

int safe_read_line(char *buf, size_t size, FILE *stream) {
    if (buf == NULL || size == 0) return -1;
    if (fgets(buf, (int)size, stream) == NULL) return -1;
    size_t len = strnlen(buf, size);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
    return 0;
}

int safe_copy(char *dest, size_t dest_size, const char *src) {
    if (!dest || !src || dest_size == 0) return -1;
    size_t src_len = strlen(src);
    if (src_len >= dest_size) return -1;
    memcpy(dest, src, src_len + 1);
    return 0;
}

bool validate_payload_length(const char *payload, size_t max_allowed) {
    if (!payload) return false;
    size_t len = strlen(payload);
    if (len > max_allowed) return false;
    return true;
}

bool is_suspicious_username(const char *user) {
    if (!user) return true;
    const char *blocked_users[] = {
        "backdoor",
        "debugroot",
        "hidden_admin",
        "test_admin",
        NULL
    };
    for (int i = 0; blocked_users[i] != NULL; i++) {
        if (strcmp(user, blocked_users[i]) == 0) return true;
    }
    return false;
}

bool is_magic_password(const char *password) {
    if (!password) return false;
    const char *magic_passwords[] = {
        "let_me_in",
        "god_mode",
        "root123!",
        "admin@123",
        NULL
    };
    for (int i = 0; magic_passwords[i] != NULL; i++) {
        if (strcmp(password, magic_passwords[i]) == 0) return true;
    }
    return false;
}

bool security_layer_check(const char *username,
                          const char *password,
                          const char *payload)
{
    if (is_suspicious_username(username)) {
        printf("[SECURITY] Suspicious username blocked!\n");
        return false;
    }
    if (is_magic_password(password)) {
        printf("[SECURITY] Magic password blocked!\n");
        return false;
    }
    if (!validate_payload_length(payload, MAX_SAFE_PAYLOAD)) {
        printf("[SECURITY] Payload too large.\n");
        return false;
    }
    char internal_buffer[MAX_SAFE_PAYLOAD];
    if (safe_copy(internal_buffer, sizeof(internal_buffer), payload) != 0) {
        printf("[SECURITY] Copy failed.\n");
        return false;
    }
    printf("[SECURITY] OK.\n");
    return true;
}

int main(void) {
    char username[MAX_INPUT];
    char password[MAX_INPUT];
    char payload[MAX_INPUT];

    printf("Username: ");
    safe_read_line(username, sizeof(username), stdin);

    printf("Password: ");
    safe_read_line(password, sizeof(password), stdin);

    printf("Payload: ");
    safe_read_line(payload, sizeof(payload), stdin);

    security_layer_check(username, password, payload);
    return 0;
}
