import AppKit
import ClavisCore

@MainActor
final class ApplicationSettingsModel: ObservableObject {
    @Published private(set) var snapshot: ApplicationRegistrySnapshot?
    @Published private(set) var isBusy = false
    @Published private(set) var message: String?
    @Published var selection: UUID?
    private let agent: AgentControlling

    init(agent: AgentControlling = AgentLifecycleManager.shared) { self.agent = agent }
    var applications: [RegisteredApplication] { snapshot?.applications.filter { !$0.removed } ?? [] }

    func load() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        let agent = agent
        snapshot = await Task.detached { agent.applicationRegistry() }.value
        message = snapshot == nil ? "Could not load applications. Check that the Clavis daemon is running and up to date." : nil
        if !applications.contains(where: { $0.id == selection }) { selection = nil }
    }

    func classify(_ app: RegisteredApplication, as classification: ApplicationClassification) async {
        guard app.classification != classification else { return }
        var changed = app
        changed.classification = classification
        await perform(.set(changed))
    }

    func removeSelected() async {
        guard let app = applications.first(where: { $0.id == selection }) else { return }
        await perform(.remove(app.identity))
    }

    func add(url: URL) async {
        guard !isBusy else { return }
        do {
            let executable = Bundle(url: url)?.executableURL ?? url
            let identity = try ApplicationIdentityVerifier.identity(forExecutable: executable)
            if let existing = applications.first(where: { $0.identity == identity }) {
                selection = existing.id
                return
            }
            let app = RegisteredApplication(
                identity: identity,
                name: url.deletingPathExtension().lastPathComponent,
                path: url.path, classification: .bot
            )
            await perform(.set(app))
            selection = applications.first(where: { $0.identity == identity })?.id
        } catch {
            message = "Could not identify the selected application or executable."
        }
    }

    private func perform(_ change: ApplicationPolicyChange) async {
        guard !isBusy, snapshot != nil else { return }
        isBusy = true
        message = nil
        defer { isBusy = false }
        let agent = agent
        let result = await Task.detached {
            let applied = agent.changeApplicationPolicy(change)
            return (applied, applied ? agent.applicationRegistry() : nil)
        }.value
        guard result.0 else {
            message = "The change was not applied. The previous policy remains in effect."
            return
        }
        guard let fresh = result.1 else {
            message = "The daemon accepted the change, but its updated settings could not be loaded."
            return
        }
        snapshot = fresh
        if !applications.contains(where: { $0.id == selection }) { selection = nil }
    }
}
