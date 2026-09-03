import NIO
@preconcurrency import NIOSSH
import Logging
import NIOConcurrencyHelpers

final class SSHClientInboundChannelHandler: Sendable {
    typealias TCPIPForwardHandler = @Sendable (Channel, SSHChannelType.ForwardedTCPIP) -> EventLoopFuture<Void>
    let forwardedTCPIPHosts = NIOLockedValueBox(
        [SSHRemotePortForward: TCPIPForwardHandler]()
    )

    init() {}

    enum HandleRegistrationResult: Error {
        case success
        case alreadyRegistered
    }

    nonisolated func registerForwardedTCPIP(host: String, port: Int, handler: @escaping TCPIPForwardHandler) -> HandleRegistrationResult {
        let bound = SSHRemotePortForward(
            host: host,
            boundPort: port
        )
        return forwardedTCPIPHosts.withLockedValue { hosts in
            if hosts.keys.contains(bound) {
                return .alreadyRegistered
            }
            hosts[bound] = handler
            return .success
        }
    }

    nonisolated func unregisterForwardedTCPIP(host: String, port: Int) {
        let bound = SSHRemotePortForward(
            host: host,
            boundPort: port
        )
        forwardedTCPIPHosts.withLockedValue { hosts in
            _ = hosts.removeValue(forKey: bound)
        }
    }

    nonisolated func handleChannel(channel: Channel, channelType: SSHChannelType) -> EventLoopFuture<Void> {
        switch channelType {
        case .session:
            return channel.eventLoop.makeFailedFuture(CitadelError.unsupported)
        case .directTCPIP:
            return channel.eventLoop.makeFailedFuture(CitadelError.unsupported)
        case .forwardedTCPIP(let forwardedTCPIP):
            return forwardedTCPIPHosts.withLockedValue { hosts in
                let bound = SSHRemotePortForward(
                    host: forwardedTCPIP.listeningHost,
                    boundPort: forwardedTCPIP.listeningPort
                )
                guard let host = hosts[bound] else {
                    return channel.eventLoop.makeFailedFuture(CitadelError.channelCreationFailed)
                }

                return host(channel, forwardedTCPIP)
            }
        }
    }
}

final class ClientHandshakeHandler: ChannelInboundHandler, Sendable {
    typealias InboundIn = Any

    private let promise: EventLoopPromise<Void>
    let logger = Logger(label: "nl.orlandos.citadel.handshake")

    /// SSH_MSG_USERAUTH_BANNER text the server sent during authentication (RFC 4252 §5.4),
    /// accumulated (a server may send several). Surfaced so clients can display it like OpenSSH.
    let issueBanner = NIOLockedValueBox<String>("")

    /// A future that will be fulfilled when the handshake is complete.
    public var authenticated: EventLoopFuture<Void> {
        promise.futureResult
    }

    init(eventLoop: EventLoop, loginTimeout: TimeAmount) {
        let promise = eventLoop.makePromise(of: Void.self)
        self.promise = promise

        eventLoop.scheduleTask(deadline: .now() + loginTimeout) {
            promise.fail(ChannelError.connectTimeout(loginTimeout))
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let banner = event as? NIOUserAuthBannerEvent {
            issueBanner.withLockedValue { $0 += banner.message }
        }
        if event is UserAuthSuccessEvent {
            self.promise.succeed(())
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        self.promise.fail(error)
    }
    
    deinit {
        struct Disconnected: Error {}
        self.promise.fail(Disconnected())
    }
}

public struct SSHClientSettings: Sendable {
    public var host: String
    public var port: Int
    public var authenticationMethod: @Sendable () -> SSHAuthenticationMethod
    public var hostKeyValidator: SSHHostKeyValidator
    public var algorithms: SSHAlgorithms = SSHAlgorithms()
    public var protocolOptions: Set<SSHProtocolOption> = []
    public var group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton
    internal var channelHandlers: [ChannelHandler & Sendable] = []
    /// Bounds the TCP connect (name resolution + connect).
    public var connectTimeout: TimeAmount = .seconds(30)
    /// Bounds the SSH handshake (version exchange + key exchange + user authentication), measured
    /// from channel initialisation. When it elapses the connect fails with
    /// `ChannelError.connectTimeout(loginTimeout)` and — for `SSHClient.connect(to:)` /
    /// `connect(host:...)` — the underlying channel is closed, so the half-open connection does not
    /// linger unauthenticated on the server (sshd counts those against `MaxStartups` until its
    /// `LoginGraceTime` reaps them). Previously hard-coded to 10 s.
    public var loginTimeout: TimeAmount = .seconds(10)
    /// Invoked with the freshly created `Channel` BEFORE the TCP connect completes (from the
    /// bootstrap's channel initialiser, on the channel's event loop — keep it quick). Lets a caller
    /// hold the channel so an in-flight handshake can be aborted with `channel.close()`: NIO's connect
    /// ignores Task cancellation, so without a handle a caller that gives up on a slow handshake has
    /// no way to release the server-side connection. May be called more than once per connect when
    /// the host resolves to several addresses (Happy Eyeballs) — close every channel you were given.
    public var onChannel: (@Sendable (Channel) -> Void)? = nil

    public init(
        host: String,
        port: Int = 22,
        authenticationMethod: @Sendable @escaping () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator
    ) {
        self.host = host
        self.port = port
        self.authenticationMethod = authenticationMethod
        self.hostKeyValidator = hostKeyValidator
    }
}

final class SSHClientSession: Sendable {
    let channel: Channel
    let sshHandler: NIOLoopBoundBox<NIOSSHHandler>
    let inboundChannelHandler: SSHClientInboundChannelHandler
    /// The server's authentication banner (SSH_MSG_USERAUTH_BANNER), if any.
    let issueBanner: String?

    init(channel: Channel, inboundChannelHandler: SSHClientInboundChannelHandler, sshHandler: NIOSSHHandler, issueBanner: String? = nil) {
        self.channel = channel
        self.inboundChannelHandler = inboundChannelHandler
        self.sshHandler = NIOLoopBoundBox(sshHandler, eventLoop: channel.eventLoop)
        self.issueBanner = issueBanner
    }
    
    /// Creates a new SSH session on the given channel. This allows you to use an existing channel for the SSH session.
    /// - authenticationMethod: The authentication method to use, see `SSHAuthenticationMethod`.
    /// - hostKeyValidator: The host key validator to use, see `SSHHostKeyValidator`.
    /// - algorithms: The algorithms to use, will use the default algorithms if not specified.
    /// - protocolOptions: The protocol options to use, will use the default options if not specified.
    /// - group: The event loop group to use, will use a new group with one thread if not specified.
    static func addHandlers(
        on channel: Channel,
        authenticationMethod: @escaping @Sendable @autoclosure () -> SSHAuthenticationMethod,
        inboundChannelHandler: SSHClientInboundChannelHandler,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = []
    ) -> EventLoopFuture<Void> {
        addHandlers(
            on: channel,
            inboundChannelHandler: SSHClientInboundChannelHandler(),
            settings: SSHClientSettings(
                host: "127.0.0.1",
                port: 22,
                authenticationMethod: authenticationMethod,
                hostKeyValidator: hostKeyValidator
            )
        )
    }

    /// Creates a new SSH session on the given channel. This allows you to use an existing channel for the SSH session.
    /// - channel: The channel to use for the SSH session, could be an existing TCP socket or proxy connection.
    /// - settings: The settings to use for the SSH session.
    static func addHandlers(
        on channel: Channel,
        inboundChannelHandler: SSHClientInboundChannelHandler,
        settings: SSHClientSettings
    ) -> EventLoopFuture<Void> {
        let handshakeHandler = ClientHandshakeHandler(
            eventLoop: channel.eventLoop,
            loginTimeout: settings.loginTimeout
        )
        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: settings.authenticationMethod(),
            serverAuthDelegate: settings.hostKeyValidator
        )
        
        settings.algorithms.apply(to: &clientConfiguration)
        
        for option in settings.protocolOptions {
            option.apply(to: &clientConfiguration)
        }
        
        do {
            try channel.pipeline.syncOperations.addHandlers(
                NIOSSHHandler(
                    role: .client(clientConfiguration),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: { channel, channelType in
                        return inboundChannelHandler.handleChannel(channel: channel, channelType: channelType)
                    }
                ),
                handshakeHandler
            )
            return channel.eventLoop.makeSucceededVoidFuture()
        } catch {
            return channel.eventLoop.makeFailedFuture(error)
        }
    }

    /// Creates a new SSH session on a new channel. This will connect to the given host and port.
    /// - settings: The settings to use for the SSH session.
    static func connect(
        settings: SSHClientSettings
    ) async throws -> SSHClientSession {
        let eventLoop = settings.group.any()
        let inboundChannelHandler = SSHClientInboundChannelHandler()
        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: settings.authenticationMethod(),
            serverAuthDelegate: settings.hostKeyValidator
        )
        
        settings.algorithms.apply(to: &clientConfiguration)
        
        for option in settings.protocolOptions {
            option.apply(to: &clientConfiguration)
        }
        
        let onChannel = settings.onChannel
        let bootstrap = ClientBootstrap(group: eventLoop).channelInitializer { channel in
            onChannel?(channel)   // hand the caller an abort handle before any byte is on the wire
            return Self.addHandlers(on: channel, inboundChannelHandler: inboundChannelHandler, settings: settings)
        }
        .connectTimeout(settings.connectTimeout)
//        .channelOption(ChannelOptions.autoRead, value: true)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)

        // The TCP connect either yields a live channel or fails having already released its socket
        // (NIO closes losing/failed Happy Eyeballs attempts itself).
        let channel = try await bootstrap.connect(host: settings.host, port: settings.port).get()
        do {
            let handshakeHandler = try await channel.pipeline.handler(type: ClientHandshakeHandler.self).get()
            try await handshakeHandler.authenticated.get()
            let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
            // Auth is complete, so any USERAUTH_BANNER has arrived — carry it onto the session.
            let banner = handshakeHandler.issueBanner.withLockedValue { $0 }
            return SSHClientSession(channel: channel, inboundChannelHandler: inboundChannelHandler, sshHandler: sshHandler, issueBanner: banner.isEmpty ? nil : banner)
        } catch {
            // The handshake failed (login timeout, host-key refusal, authentication rejected, KEX or
            // protocol error) but the TCP channel is still open: `ClientHandshakeHandler` only fails
            // its promise, NIOSSHHandler only closes on an inbound DISCONNECT, and NIO does not close a
            // channel on an unhandled error. Left alone, the connection sits half-open on the server —
            // unauthenticated, counting against sshd's MaxStartups — until LoginGraceTime reaps it,
            // and the caller has no handle to close it (nothing was returned). Close it here so the
            // FIN goes out immediately and the failure releases the server-side slot at once.
            channel.close(promise: nil)
            throw error
        }
    }
    
    /// Creates a new SSH session on a new channel. This will connect to the given host and port.
    /// - Parameters:
    ///  - host: The host to connect to.
    /// - port: The port to connect to.
    /// - authenticationMethod: The authentication method to use, see `SSHAuthenticationMethod`.
    /// - hostKeyValidator: The host key validator to use, see `SSHHostKeyValidator`.
    /// - algorithms: The algorithms to use, will use the default algorithms if not specified.
    /// - protocolOptions: The protocol options to use, will use the default options if not specified.
    /// - group: The event loop group to use, will use a new group with one thread if not specified.
    /// - channelHandlers: Pass in an array of channel prehandlers that execute first. Default empty array
    /// - connectTimeout: Pass in the time before the connection times out. Default 30 seconds.
    /// - loginTimeout: Bound on the SSH handshake after the TCP connect. Default 10 seconds.
    /// - onChannel: Receives the channel before connecting (abort handle). See `SSHClientSettings.onChannel`.
    static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: @Sendable @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = [],
        group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        channelHandlers: [ChannelHandler] = [],
        connectTimeout: TimeAmount = .seconds(30),
        loginTimeout: TimeAmount = .seconds(10),
        onChannel: (@Sendable (Channel) -> Void)? = nil
    ) async throws -> SSHClientSession {
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator
        )

        settings.algorithms = algorithms
        settings.protocolOptions = protocolOptions
        settings.group = group
        settings.channelHandlers = channelHandlers
        settings.connectTimeout = connectTimeout
        settings.loginTimeout = loginTimeout
        settings.onChannel = onChannel

        return try await connect(
            settings: settings
        )
    }
}

public struct InvalidHostKey: Error, Equatable {}

/// A host key validator that can be used to validate an SSH host key. This can be used to validate the host key against a set of trusted keys, or to accept any key.
public struct SSHHostKeyValidator: NIOSSHClientServerAuthenticationDelegate, Sendable {
    private enum Method {
        case trustedKeys(Set<NIOSSHPublicKey>)
        case acceptAnything
        case custom(NIOSSHClientServerAuthenticationDelegate)
    }
    
    private let method: Method
    
    public func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        switch method {
        case .trustedKeys(let keys):
            if keys.contains(hostKey) {
                validationCompletePromise.succeed(())
            } else {
                validationCompletePromise.fail(InvalidHostKey())
            }
        case .acceptAnything:
            validationCompletePromise.succeed(())
        case .custom(let validator):
            validator.validateHostKey(hostKey: hostKey, validationCompletePromise: validationCompletePromise)
        }
    }
    
    /// Creates a new host key validator that will validate the host key against the given set of trusted keys. If the host key is not in the set, the validation will fail.
    /// - Parameter keys: The set of trusted keys.
    public static func trustedKeys(_ keys: Set<NIOSSHPublicKey>) -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .trustedKeys(keys))
    }
    
    /// Creates a new host key validator that will accept any host key. This is not recommended for production use.
    public static func acceptAnything() -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .acceptAnything)
    }
    
    /// Creates a new host key validator that will use the given custom validator. This can be used to implement custom host key validation logic.
    public static func custom(_ validator: NIOSSHClientServerAuthenticationDelegate) -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .custom(validator))
    }
}
