import NIO
import NIOSSH
import Crypto
import NIOConcurrencyHelpers

/// Answers keyboard-interactive challenges with a stored password — the RFC 4256 fallback for
/// servers with `PasswordAuthentication no` + `KbdInteractiveAuthentication yes` (UniFi/UDM,
/// cPanel, hardened sshd). Single-prompt servers only; a true multi-prompt (password + OTP) 2FA
/// server would need an interactive delegate.
///
/// Also captures the challenge's `name`/`instruction` text into `bannerBox`: servers frequently
/// deliver the login notice/MOTD there (rather than as a USERAUTH_BANNER), and it would otherwise
/// be lost. The client can display it like `ssh` does.
final class PasswordKeyboardInteractiveDelegate: NIOSSHKeyboardInteractiveDelegate {
    let password: String
    let bannerBox: NIOLockedValueBox<String>
    init(password: String, bannerBox: NIOLockedValueBox<String>) {
        self.password = password
        self.bannerBox = bannerBox
    }
    func respondToKeyboardInteractiveChallenge(
        name: String,
        instruction: String,
        prompts: [NIOSSHKeyboardInteractivePrompt]
    ) -> [String] {
        let extra = [name, instruction].filter { !$0.isEmpty }.joined(separator: "\n")
        if !extra.isEmpty {
            bannerBox.withLockedValue { $0 += ($0.isEmpty ? "" : "\n") + extra }
        }
        return prompts.map { _ in self.password }
    }
}

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
    }
    
    private let allImplementations: [Implementation]
    private var implementations: [Implementation]
    private var enableKeyboardInteractiveFallback: Bool = false

    /// Login notice/MOTD captured from a keyboard-interactive challenge's name/instruction, if any.
    private(set) var capturedBanner = NIOLockedValueBox<String>("")
    /// The captured keyboard-interactive banner text (nil if the server sent none). Read after connect.
    public var receivedBanner: String? {
        let b = capturedBanner.withLockedValue { $0 }
        return b.isEmpty ? nil : b
    }
    
    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.allImplementations = [.user(username, offer: offer)]
        self.implementations = allImplementations
    }

    private init(implementations: [Implementation]) {
        self.allImplementations = implementations
        self.implementations = implementations
    }
    
    internal init(
        custom: NIOSSHClientUserAuthenticationDelegate
    ) {
        self.allImplementations = [.custom(custom)]
        self.implementations = allImplementations
    }
    
    /// Creates a password based authentication method.
    /// - Parameters:
    ///  - username: The username to authenticate with.
    /// - password: The password to authenticate with.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        // Offer password first, then keyboard-interactive with the SAME password (RFC 4256). This
        // covers BOTH cases: the server not advertising `password` at all, AND advertising it but
        // rejecting it (UniFi/UDM, hardened sshd) — nextAuthenticationType skips unavailable methods
        // and the KI attempt is also tried after a password rejection.
        let bannerBox = NIOLockedValueBox<String>("")
        let ki: NIOSSHUserAuthenticationOffer.Offer = .keyboardInteractive(.init(delegate: PasswordKeyboardInteractiveDelegate(password: password, bannerBox: bannerBox)))
        let method = SSHAuthenticationMethod(implementations: [
            .user(username, offer: .password(.init(password: password))),
            .user(username, offer: ki),
        ])
        method.enableKeyboardInteractiveFallback = true
        method.capturedBanner = bannerBox   // share the box the KI delegate writes into
        return method
    }

    /// Password auth WITHOUT the keyboard-interactive fallback.
    public static func passwordBasedStrict(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }
    
    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
    }
    
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if implementations.isEmpty {
            nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
            return
        }
        
        // Try queued methods in order, SKIPPING any the server doesn't advertise, until one matches
        // or we run out. This is what lets password → keyboard-interactive fallback work whether the
        // server omits password or advertises-then-rejects it.
        while let implementation = implementations.first {
            implementations.removeFirst()
            switch implementation {
            case .user(let username, offer: let offer):
                let available: Bool
                switch offer {
                case .password:          available = availableMethods.contains(.password)
                case .keyboardInteractive: available = availableMethods.contains(.keyboardInteractive)
                case .hostBased:         available = availableMethods.contains(.hostBased)
                case .privateKey:        available = availableMethods.contains(.publicKey)
                case .none:              available = true
                }
                if !available { continue }   // server doesn't offer this method — try the next queued one
                nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: offer))
                return
            case .custom(let implementation):
                implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
                return
            }
        }
        nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
    }
}
