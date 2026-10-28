import Security

func store() {
    // ruleid: keychain-accessible-always
    let a = [kSecAttrAccessible: kSecAttrAccessibleAlways]
    // ruleid: keychain-accessible-always
    let b = [kSecAttrAccessible: kSecAttrAccessibleAlwaysThisDeviceOnly]
    // ok: keychain-accessible-always
    let c = [kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    // ok: keychain-accessible-always
    let d = [kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock]
}
