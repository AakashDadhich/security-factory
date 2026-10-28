import CryptoKit
import CommonCrypto

func hashes(data: Data) {
    // ruleid: weak-hash-md5-sha1
    let a = Insecure.MD5.hash(data: data)
    // ruleid: weak-hash-md5-sha1
    let b = Insecure.SHA1.hash(data: data)
    // ruleid: weak-hash-md5-sha1
    CC_MD5(bytes, len, &digest)
    // ok: weak-hash-md5-sha1
    let c = SHA256.hash(data: data)
}
