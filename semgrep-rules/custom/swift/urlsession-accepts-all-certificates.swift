import Foundation

class Bad: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // ruleid: urlsession-accepts-all-certificates
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}

class Good: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let trust = challenge.protectionSpace.serverTrust!
        let trusted = SecTrustEvaluateWithError(trust, nil)
        if !trusted {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        // ok: urlsession-accepts-all-certificates
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
