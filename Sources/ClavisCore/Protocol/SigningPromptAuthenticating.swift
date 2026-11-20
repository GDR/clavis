import Foundation
import LocalAuthentication
import Darwin

/// Describes a live signing or SSH authentication request routed from `clavis-agent`
/// to an interactive prompt presenter (such as the MacBook Notch Island overlay).
public struct SigningAuthenticationRequest: @unchecked Sendable {
    public let key: SSHKeyInfo
    public let operation: KeyOperation
    public let operationLabel: String
    public let callerName: String?
    public let peerPid: pid_t
    public let peerPath: String
    public let allowsSessionScope: Bool
    public let defaultScope: KeyGracePeriod
    public let reason: String
    public let isUncertainCaller: Bool
    public let isForwardedAgent: Bool

    public init(
        key: SSHKeyInfo,
        operation: KeyOperation,
        operationLabel: String,
        callerName: String?,
        peerPid: pid_t,
        peerPath: String,
        allowsSessionScope: Bool,
        defaultScope: KeyGracePeriod,
        reason: String,
        isUncertainCaller: Bool,
        isForwardedAgent: Bool
    ) {
        self.key = key
        self.operation = operation
        self.operationLabel = operationLabel
        self.callerName = callerName
        self.peerPid = peerPid
        self.peerPath = peerPath
        self.allowsSessionScope = allowsSessionScope
        self.defaultScope = defaultScope
        self.reason = reason
        self.isUncertainCaller = isUncertainCaller
        self.isForwardedAgent = isForwardedAgent
    }
}

/// Authenticated `LAContext` and user-chosen session scope returned by `SigningPromptAuthenticating`.
public struct SigningAuthenticationOutcome: @unchecked Sendable {
    public let context: LAContext
    public let selectedScope: KeyGracePeriod

    public init(context: LAContext, selectedScope: KeyGracePeriod) {
        self.context = context
        self.selectedScope = selectedScope
    }
}

/// Decoupled presenter boundary allowing `ClavisCore` (`SigningPolicyEvaluator`) to request
/// native GUI notch authentication in `ClavisPromptUI` without importing AppKit/SwiftUI.
public protocol SigningPromptAuthenticating: AnyObject, Sendable {
    func authenticateSigningRequest(_ request: SigningAuthenticationRequest) throws -> SigningAuthenticationOutcome
}
