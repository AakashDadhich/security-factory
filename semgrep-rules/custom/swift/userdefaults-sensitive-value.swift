import Foundation

func save(token: String, theme: String) {
    // ruleid: userdefaults-sensitive-value
    UserDefaults.standard.set(token, forKey: "session")
    // ruleid: userdefaults-sensitive-value
    UserDefaults.standard.set("abc", forKey: "authToken")
    // ruleid: userdefaults-sensitive-value
    UserDefaults.standard.set(value, forKey: "userPassword")
    // ok: userdefaults-sensitive-value
    UserDefaults.standard.set(theme, forKey: "theme")
}
