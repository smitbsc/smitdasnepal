  GNU nano 7.2                            security_layer_demo.cpp
        return 0;
    }

    if (!validatePassword(password)) {
        logEvent("Invalid password pattern detected");
        std::cout << "Invalid password\n";
        return 0;
    }

    if (authenticateSafe(username, password)) {
        logEvent("Authentication success for user: " + username);
        std::cout << "Access granted\n";
    } else {
        logEvent("Authentication failed for user: " + username);
        std::cout << "Access denied\n";
    }

    return 0;
}



^G Help       ^O Write Out  ^W Where Is   ^K Cut        ^T Execute    ^C Location   M-U Undo
^X Exit       ^R Read File  ^\ Replace    ^U Paste      ^J Justify    ^/ Go To Line M-E Redo
