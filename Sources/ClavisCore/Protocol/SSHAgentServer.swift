import Foundation
import Network
import Darwin

public enum SSHAgentServerError: LocalizedError, Equatable {
    case socketAlreadyInUse(String)
    case socketCreationFailed(Int32)
    case socketBindFailed(String, Int32)
    case socketListenFailed(Int32)
    case socketOptionFailed(Int32)
    case unsafeSocketPath(String)
    case socketPermissionFailed(String, Int32)
    case pathTooLong(String)

    public var errorDescription: String? {
        switch self {
        case .socketAlreadyInUse(let path):
            return "Another SSH agent is actively listening on socket at \(path)"
        case .socketCreationFailed(let code):
            return "Failed to create socket (errno: \(code))"
        case .socketBindFailed(let path, let code):
            return "Failed to bind socket at \(path) (errno: \(code))"
        case .socketListenFailed(let code):
            return "Failed to listen on socket (errno: \(code))"
        case .socketOptionFailed(let code):
            return "Failed to configure socket security options (errno: \(code))"
        case .unsafeSocketPath(let path):
            return "Refusing unsafe SSH agent socket path: \(path)"
        case .socketPermissionFailed(let path, let code):
            return "Failed to enforce SSH agent socket permissions at \(path) (errno: \(code))"
        case .pathTooLong(let path):
            return "Socket path is too long: \(path)"
        }
    }
}

/// Process instance that a Git signing grant was approved for.
public struct GitApprovedProcess: Equatable, Sendable {
    public let pid: pid_t
    public let startTime: UInt64
    public let path: String?

    public init(pid: pid_t, startTime: UInt64, path: String? = nil) {
        self.pid = pid
        self.startTime = startTime
        self.path = path
    }
}

public class SSHAgentServer {
    internal static let invalidateKeyRequest: UInt8 = 240
    internal static let queryGitGraceRequest: UInt8 = 241
    internal static let lockAllRequest: UInt8 = 242
    internal static let registerAgentSessionRequest: UInt8 = 243
    internal static let endAgentSessionRequest: UInt8 = 244
    internal static let listAgentSessionsRequest: UInt8 = 245
    internal static let revokeAllAgentSessionsRequest: UInt8 = 246
    internal static let extendAgentSessionRequest: UInt8 = 247
    internal static let setAgentPolicyRequest: UInt8 = 248
    internal static let getAgentPolicyRequest: UInt8 = 249
    public static let defaultSocketPath = NSString(string: "~/.ssh/clavis.sock").expandingTildeInPath
    public static let defaultAgentSocketPath = NSString(string: "~/.ssh/clavis-agent.sock").expandingTildeInPath
    public static let shared = SSHAgentServer(promptGate: .shared)
    public static let sharedInstance = shared
    public static let agentShared = SSHAgentServer(socketPath: defaultAgentSocketPath, role: .agent, promptGate: .shared)

    public static let defaultMaxConnectionLifetime: TimeInterval = 120.0
    public static let defaultMaxRequestsPerConnection: Int = 200

    public let socketPath: String
    public let role: AgentSocketRole

    private var socketServer: UnixSocketServer!
    private let signingPolicyEvaluator: SigningPolicyEvaluator
    private let controlDispatcher: AgentControlDispatcher
    private let keyManager: KeychainManager
    #if DEBUG
    public var testContext: TestContext?
    #endif

    public var onPermanentListenerFailure: (() -> Void)? {
        get { socketServer.onPermanentListenerFailure }
        set { socketServer.onPermanentListenerFailure = newValue }
    }

    internal var boundInode: ino_t? { socketServer.boundInode }
    internal var boundDevice: dev_t? { socketServer.boundDevice }
    public var isSocketActive: Bool { socketServer.isSocketActive }
    internal var activeClientCount: Int { socketServer.activeClientCount }

    public init(
        socketPath: String = SSHAgentServer.defaultSocketPath,
        role: AgentSocketRole = .personal,
        maxConcurrentClients: Int = 32,
        maxConcurrentClientsPerPID: Int = 8,
        maxConcurrentClientsPerExecutable: Int? = nil,
        clientIdleTimeout: TimeInterval = 30,
        handshakeTimeout: TimeInterval = 2.0,
        maxConnectionLifetime: TimeInterval = SSHAgentServer.defaultMaxConnectionLifetime,
        maxRequestsPerConnection: Int = SSHAgentServer.defaultMaxRequestsPerConnection,
        keyManager: KeychainManager = .shared,
        promptGate: SigningPromptGate = SigningPromptGate(),
        gitSigningGraceManager: GitSigningGraceManager = .shared,
        controlPeerValidator: ((Int32) -> Bool)? = nil,
        peerProcessValidator: ((pid_t, String, UInt64) -> Bool)? = nil,
        backoffHandler: ((useconds_t) -> Void)? = nil,
        acceptCall: ((Int32) -> (fd: Int32, err: Int32))? = nil,
        onPermanentListenerFailure: (() -> Void)? = nil,
        auditRecorder: AuditRecording = AuditRecorder.shared,
        agentSessions: AgentSessionRegistry = .shared,
        agentPolicies: AgentPolicyStoring = KeychainAgentPolicyStore(),
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        notificationPoster: @escaping (String, [String: String]) -> Void = { name, userInfo in
            DistributedNotificationCenter.default().postNotificationName(
                NSNotification.Name(name),
                object: nil,
                userInfo: userInfo,
                deliverImmediately: true
            )
        },
        testContext: TestContext? = nil
    ) {
        self.socketPath = socketPath
        self.role = role
        self.keyManager = keyManager
        #if DEBUG
        self.testContext = testContext ?? keyManager.testContext ?? TestContextScope.current
        #endif

        let resolvedPeerValidator = peerProcessValidator ?? { SSHAgentServer.peerProcessUnchanged(pid: $0, path: $1, startTime: $2) }

        self.controlDispatcher = AgentControlDispatcher(
            keyManager: keyManager,
            auditRecorder: auditRecorder,
            agentSessions: agentSessions,
            agentPolicies: agentPolicies,
            authenticator: authenticator,
            promptGate: promptGate,
            peerProcessValidator: resolvedPeerValidator,
            gitSigningGraceManager: gitSigningGraceManager
        )

        self.signingPolicyEvaluator = SigningPolicyEvaluator(
            keyManager: keyManager,
            gitSigningGraceManager: gitSigningGraceManager,
            promptGate: promptGate,
            agentSessions: agentSessions,
            auditRecorder: auditRecorder,
            agentPolicies: agentPolicies,
            authenticator: authenticator,
            notificationPoster: notificationPoster,
            peerProcessValidator: resolvedPeerValidator
        )

        let config = UnixSocketServer.Configuration(
            socketPath: socketPath,
            maxClients: max(1, maxConcurrentClients),
            maxClientsPerPID: max(1, maxConcurrentClientsPerPID),
            maxClientsPerExecutable: maxConcurrentClientsPerExecutable.map { max(1, $0) },
            clientLifetime: max(0.01, maxConnectionLifetime),
            maxRequestsPerConnection: max(1, maxRequestsPerConnection),
            clientTimeout: max(0.1, clientIdleTimeout)
        )

        self.socketServer = UnixSocketServer(
            configuration: config,
            handshakeTimeout: max(0.05, min(clientIdleTimeout, handshakeTimeout)),
            controlPeerValidator: controlPeerValidator,
            peerProcessValidator: peerProcessValidator,
            backoffHandler: backoffHandler,
            acceptCall: acceptCall,
            onPermanentListenerFailure: onPermanentListenerFailure,
            logger: { ClavisLogger.log("SSH_AGENT", $0) },
            requestHandler: { [weak self] payload, pid, path, start, sock, conn, isTrusted in
                guard let self = self else { return Data([5]) }
                #if DEBUG
                if let context = self.testContext {
                    return TestContextScope.$current.withValue(context) {
                        self.processAgentRequest(
                            payload: payload,
                            clientPid: pid,
                            clientExecutablePath: path,
                            clientStartTime: start,
                            clientSocket: sock,
                            connection: conn,
                            isTrustedControlPeer: isTrusted
                        )
                    }
                }
                #endif
                return self.processAgentRequest(
                    payload: payload,
                    clientPid: pid,
                    clientExecutablePath: path,
                    clientStartTime: start,
                    clientSocket: sock,
                    connection: conn,
                    isTrustedControlPeer: isTrusted
                )
            }
        )
    }

    public func start() throws {
        try socketServer.start()
    }

    public func stop() {
        socketServer.stop()
    }

    internal func reserveClientSlot(clientPid: pid_t? = nil, clientExecutablePath: String? = nil) -> Bool {
        socketServer.reserveClientSlot(clientPid: clientPid, clientExecutablePath: clientExecutablePath)
    }

    internal func releaseClientSlot(clientPid: pid_t? = nil, clientExecutablePath: String? = nil) {
        socketServer.releaseClientSlot(clientPid: clientPid, clientExecutablePath: clientExecutablePath)
    }

    internal func acceptLoop() {
        socketServer.acceptLoop()
    }

    internal func handleClient(
        socket clientSocket: Int32,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil
    ) {
        socketServer.handleClient(
            socket: clientSocket,
            clientPid: clientPid,
            clientExecutablePath: clientExecutablePath,
            clientStartTime: clientStartTime
        )
    }

    internal func processAgentRequest(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil,
        connection: AgentConnectionState? = nil,
        isTrustedControlPeer: () -> Bool = { false }
    ) -> Data {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return TestContextScope.$current.withValue(context) {
                self.processAgentRequestInternal(
                    payload: payload,
                    clientPid: clientPid,
                    clientExecutablePath: clientExecutablePath,
                    clientStartTime: clientStartTime,
                    clientSocket: clientSocket,
                    connection: connection,
                    isTrustedControlPeer: isTrustedControlPeer
                )
            }
        }
        #endif
        return processAgentRequestInternal(
            payload: payload,
            clientPid: clientPid,
            clientExecutablePath: clientExecutablePath,
            clientStartTime: clientStartTime,
            clientSocket: clientSocket,
            connection: connection,
            isTrustedControlPeer: isTrustedControlPeer
        )
    }

    private func processAgentRequestInternal(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil,
        connection: AgentConnectionState? = nil,
        isTrustedControlPeer: () -> Bool = { false }
    ) -> Data {
        guard !payload.isEmpty else { return Data([5]) } // SSH_AGENT_FAILURE (5)
        let msgType = payload[0]
        ClavisLogger.log("SSH_AGENT_REQ", "Received SSH Agent request type \(msgType)")

        if AgentControlDispatcher.isControlOpcode(msgType) {
            let clientDesc = clientPid.map { "PID \($0)" } ?? "unknown peer"
            if role == .agent {
                ClavisLogger.log("SECURITY_ALERT", "Refused control request type \(msgType) on agent socket (\(clientDesc)).")
                return Data([5]) // SSH_AGENT_FAILURE
            }
            if !isTrustedControlPeer() {
                ClavisLogger.log("SECURITY_ALERT", "Refused control request type \(msgType) from untrusted peer (\(clientDesc)).")
                return Data([5]) // SSH_AGENT_FAILURE
            }
            return controlDispatcher.dispatch(
                msgType: msgType,
                payload: payload,
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        }

        switch msgType {
        case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
            guard payload.count == 1 else { return Data([5]) }
            return handleRequestIdentities(clientPid: clientPid, clientExecutablePath: clientExecutablePath)
        case 13: // SSH2_AGENTC_SIGN_REQUEST
            return handleSignRequest(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket,
                connection: connection
            )
        case 27: // SSH_AGENTC_EXTENSION
            var reader = DataReader(data: Data(payload.dropFirst()))
            guard let extensionType = reader.readWireString(),
                  extensionType == "session-bind@openssh.com",
                  let hostKeyBlob = reader.readWireData(),
                  let sessionID = reader.readWireData(),
                  let signatureBlob = reader.readWireData(),
                  let isForwarding = reader.readBool(),
                  reader.isEOF else {
                return Data([5])
            }
            guard let connection = connection else { return Data([5]) }
            let binding = SessionBinding(hostKeyBlob: hostKeyBlob, sessionID: sessionID, isForwarding: isForwarding)
            guard connection.bind(binding, signature: signatureBlob) else {
                return Data([5])
            }
            return Data([6]) // SSH_AGENT_SUCCESS
        default:
            ClavisLogger.log("SSH_AGENT_REQ", "Unsupported SSH Agent request type \(msgType)")
            return Data([5]) // SSH_AGENT_FAILURE
        }
    }

    internal func handleRequestIdentities(
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil
    ) -> Data {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return TestContextScope.$current.withValue(context) {
                self.handleRequestIdentities(clientPid: clientPid, clientExecutablePath: clientExecutablePath)
            }
        }
        #endif
        let clientDesc: String
        if let pid = clientPid, let path = clientExecutablePath ?? SSHAgentServer.getProcessPath(pid: pid) {
            clientDesc = "\(Self.safeProcessPath(path)) (PID \(pid))"
        } else {
            clientDesc = "local process"
        }
        ClavisLogger.log("SSH_AGENT_IDENTITIES", "Listing active SSH identities for \(clientDesc)...")
        // Filter keys according to socket role (personal lists general; agent lists agent)
        let keys = ((try? keyManager.listKeys()) ?? []).filter { role.listedPurposes.contains($0.purpose) }
        var response = Data()
        response.append(12) // SSH2_AGENT_IDENTITIES_ANSWER

        var count = UInt32(keys.count).bigEndian
        Swift.withUnsafeBytes(of: &count) { response.append(contentsOf: $0) }

        for key in keys {
            response.appendWireData(key.publicKeyBlob)
            response.appendWireString(key.label)
        }
        ClavisLogger.log("SSH_AGENT_IDENTITIES", "Returned \(keys.count) identity(ies) (0 Touch ID prompts).")
        return response
    }

    internal func handleSignRequest(
        payload: Data,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil,
        connection: AgentConnectionState? = nil
    ) -> Data {
        #if DEBUG
        if let context = self.testContext, TestContextScope.current == nil {
            return TestContextScope.$current.withValue(context) {
                self.handleSignRequest(
                    payload: payload,
                    clientPid: clientPid,
                    clientExecutablePath: clientExecutablePath,
                    clientStartTime: clientStartTime,
                    clientSocket: clientSocket,
                    connection: connection
                )
            }
        }
        #endif
        return signingPolicyEvaluator.handleSignRequest(
            payload: payload,
            role: role,
            clientPid: clientPid,
            clientExecutablePath: clientExecutablePath,
            clientStartTime: clientStartTime,
            clientSocket: clientSocket,
            connection: connection
        )
    }

    // MARK: - Static Forwarding & Utility Methods

    public static func isSocketListening(atPath path: String = defaultSocketPath) -> Bool {
        UnixSocketServer.isSocketListening(atPath: path)
    }

    public static func isPermanentSocketError(_ errorCode: Int32) -> Bool {
        UnixSocketServer.isPermanentSocketError(errorCode)
    }

    public static func getProcessName(pid: pid_t) -> String? {
        ProcessInspector.getProcessName(pid: pid)
    }

    public static func getProcessPath(pid: pid_t) -> String? {
        ProcessInspector.getProcessPath(pid: pid)
    }

    static func processStartTime(pid: pid_t) -> UInt64? {
        ProcessInspector.processStartTime(pid: pid)
    }

    static func processParentSnapshot(pid: pid_t) -> ProcessParentSnapshot? {
        ProcessInspector.processParentSnapshot(pid: pid)
    }

    public static let trustedGitPaths: Set<String> = ProcessInspector.trustedGitPaths
    public static let trustedSignerHelperPaths: Set<String> = ProcessInspector.trustedSignerHelperPaths
    public static let trustedSshPaths: Set<String> = ProcessInspector.trustedSshPaths

    static func isTrustedGitExecutable(path: String) -> Bool {
        ProcessInspector.isTrustedGitExecutable(path: path)
    }

    static func isTrustedSignerHelperExecutable(path: String) -> Bool {
        ProcessInspector.isTrustedSignerHelperExecutable(path: path)
    }

    static func isTrustedSshBinary(path: String) -> Bool {
        ProcessInspector.isTrustedSshBinary(path: path)
    }

    public static func isValidSSH2UserAuthRequest(
        _ data: Data,
        expectedSessionID: Data? = nil,
        expectedKeyBlob: Data? = nil,
        expectedHostKeyBlob: Data? = nil
    ) -> Bool {
        SessionBind.isValidSSH2UserAuthRequest(
            data,
            expectedSessionID: expectedSessionID,
            expectedKeyBlob: expectedKeyBlob,
            expectedHostKeyBlob: expectedHostKeyBlob
        )
    }

    public static func extractHostKeyFromUserAuthRequest(_ data: Data) -> Data? {
        SessionBind.extractHostKeyFromUserAuthRequest(data)
    }

    static func gitGrantCoversPeer(
        peerPid: pid_t,
        peerStartTime: UInt64,
        peerPath: String? = nil,
        approvedPid: pid_t,
        approvedStartTime: UInt64,
        processInfo: (pid_t) -> ProcessParentSnapshot? = { processParentSnapshot(pid: $0) },
        processPathLookup: (pid_t) -> String? = { getProcessPath(pid: $0) },
        resolvedGpgSSHProgram: () -> String? = { gpgSSHProgramResolver() }
    ) -> Bool {
        ProcessInspector.gitGrantCoversPeer(
            peerPid: peerPid,
            peerStartTime: peerStartTime,
            peerPath: peerPath,
            approvedPid: approvedPid,
            approvedStartTime: approvedStartTime,
            processInfo: processInfo,
            processPathLookup: processPathLookup,
            resolvedGpgSSHProgram: resolvedGpgSSHProgram
        )
    }

    static func gitGrantCoversPeer(peer: GitApprovedProcess, approved: GitApprovedProcess) -> Bool {
        ProcessInspector.gitGrantCoversPeer(peer: peer, approved: approved)
    }

    private static let resolverLock = NSLock()
    private static var _customGpgSSHProgramResolver: (@Sendable () -> String?)?

    public static var gpgSSHProgramResolver: @Sendable () -> String? {
        get {
            return {
                #if DEBUG
                if let context = TestContextScope.current, let resolver = context.gpgSSHProgramResolver {
                    return resolver()
                }
                #endif
                resolverLock.lock()
                let custom = _customGpgSSHProgramResolver
                resolverLock.unlock()
                if let custom {
                    return custom()
                }
                return resolveGpgSSHProgram()
            }
        }
        set {
            resolverLock.lock()
            _customGpgSSHProgramResolver = newValue
            resolverLock.unlock()
        }
    }

    public static func resetGpgSSHProgramResolverForTesting() {
        resolverLock.lock()
        _customGpgSSHProgramResolver = nil
        resolverLock.unlock()
    }

    static func resolveGpgSSHProgram(
        gitExecutablePath: String? = nil,
        environment: [String: String]? = nil,
        timeout: TimeInterval = 2.0
    ) -> String? {
        ProcessInspector.resolveGpgSSHProgram(
            gitExecutablePath: gitExecutablePath,
            environment: environment,
            timeout: timeout
        )
    }

    static func isSignerHelper(
        path: String,
        resolvedGpgSSHProgram: () -> String? = { gpgSSHProgramResolver() }
    ) -> Bool {
        ProcessInspector.isSignerHelper(path: path, resolvedGpgSSHProgram: resolvedGpgSSHProgram)
    }

    static func isRefusedAnchor(pid: pid_t, path: String) -> Bool {
        ProcessInspector.isRefusedAnchor(pid: pid, path: path)
    }

    static func grantAnchor(
        peerPid: pid_t,
        peerPath: String,
        processInfo: (pid_t) -> ProcessParentSnapshot? = { processParentSnapshot(pid: $0) },
        processPathLookup: (pid_t) -> String? = { getProcessPath(pid: $0) },
        resolvedGpgSSHProgram: () -> String? = { gpgSSHProgramResolver() }
    ) -> GitApprovedProcess? {
        ProcessInspector.grantAnchor(
            peerPid: peerPid,
            peerPath: peerPath,
            processInfo: processInfo,
            processPathLookup: processPathLookup,
            resolvedGpgSSHProgram: resolvedGpgSSHProgram
        )
    }

    static func grantAnchor(peerPid: pid_t, peerPath: String) -> GitApprovedProcess? {
        ProcessInspector.grantAnchor(peerPid: peerPid, peerPath: peerPath)
    }

    static func peerProcessUnchanged(pid: pid_t, path: String, startTime: UInt64) -> Bool {
        ProcessInspector.peerProcessUnchanged(pid: pid, path: path, startTime: startTime)
    }

    public static func resolveClientIdentity(pid: pid_t, processPath: String) -> String {
        ProcessInspector.resolveClientIdentity(pid: pid, processPath: processPath)
    }

    static func sshAuthenticationReason(keyLabel: String) -> String {
        SigningPolicyEvaluator.sshAuthenticationReason(keyLabel: keyLabel)
    }

    static func sshAuthenticationReason(keyLabel: String, requester: String) -> String {
        SigningPolicyEvaluator.sshAuthenticationReason(keyLabel: keyLabel, requester: requester)
    }

    static func signatureReason(
        keyLabel: String,
        requester: String,
        processPath: String,
        dataToSign: Data,
        keyBlob: Data? = nil,
        hasForwarding: Bool = false
    ) -> String {
        SigningPolicyEvaluator.signatureReason(
            keyLabel: keyLabel,
            requester: requester,
            processPath: processPath,
            dataToSign: dataToSign,
            keyBlob: keyBlob,
            hasForwarding: hasForwarding
        )
    }

    static func signatureReason(keyLabel: String, requester: String, processPath: String) -> String {
        SigningPolicyEvaluator.signatureReason(keyLabel: keyLabel, requester: requester, processPath: processPath)
    }

    static func dataSigningReason(keyLabel: String, requester: String) -> String {
        SigningPolicyEvaluator.dataSigningReason(keyLabel: keyLabel, requester: requester)
    }

    static func gitCommitSigningReason(keyLabel: String, requester: String) -> String {
        SigningPolicyEvaluator.gitCommitSigningReason(keyLabel: keyLabel, requester: requester)
    }

    static func gitCommitSigningReason(keyLabel: String) -> String {
        SigningPolicyEvaluator.gitCommitSigningReason(keyLabel: keyLabel)
    }

    static func gitSigningSessionReason(keyLabel: String) -> String {
        SigningPolicyEvaluator.gitSigningSessionReason(keyLabel: keyLabel)
    }

    static func requesterDescription(processPath: String, pid: pid_t) -> String {
        SigningPolicyEvaluator.requesterDescription(processPath: processPath, pid: pid)
    }

    private static func safeProcessPath(_ path: String) -> String {
        SigningPolicyEvaluator.safeProcessPath(path)
    }
}
