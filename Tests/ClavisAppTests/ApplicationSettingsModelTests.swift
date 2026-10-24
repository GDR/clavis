import Foundation
import Testing
@testable import Clavis
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite @MainActor struct ApplicationSettingsModelTests {
    private func application() throws -> RegisteredApplication {
        RegisteredApplication(identity: try .init(kind: .designatedRequirement, value: "test"), name: "App", path: "/App.app", classification: .bot)
    }

    @Test func unavailableDaemonDoesNotInventAnEmptyRegistry() async {
        let model = ApplicationSettingsModel(agent: MockAgentController())
        await model.load()
        #expect(model.snapshot == nil)
        #expect(model.message != nil)
        #expect(!model.isBusy)
    }

    @Test func personalClassificationStaysInTheSameList() async throws {
        let agent = MockAgentController()
        let app = try application()
        agent.stubbedApplicationRegistry = .init(applications: [app], requestsPaused: true)
        agent.applicationPolicyHandler = { change in
            guard case .set(let changed) = change else { return false }
            agent.stubbedApplicationRegistry = .init(applications: [changed], requestsPaused: true)
            return true
        }
        let model = ApplicationSettingsModel(agent: agent)
        await model.load()
        model.selection = app.id
        await model.classify(app, as: .personal)
        #expect(model.applications.count == 1)
        #expect(model.applications.first?.classification == .personal)
        #expect(model.selection == app.id)
        #expect(model.snapshot?.isPaused == true)
        #expect(model.message == nil)
    }

    @Test func cancelledOrFailedChangePreservesPreviousSelectionAndPolicy() async throws {
        let agent = MockAgentController()
        let app = try application()
        let original = ApplicationRegistrySnapshot(applications: [app])
        agent.stubbedApplicationRegistry = original
        let model = ApplicationSettingsModel(agent: agent)
        await model.load()
        model.selection = app.id
        await model.classify(app, as: .personal)
        #expect(model.snapshot == original)
        #expect(model.selection == app.id)
        #expect(model.message?.contains("not applied") == true)
    }

    @Test func removalUsesConfirmedTombstoneAndClearsSelection() async throws {
        let agent = MockAgentController()
        let app = try application()
        agent.stubbedApplicationRegistry = .init(applications: [app])
        agent.applicationPolicyHandler = { change in
            guard case .remove(let identity) = change, identity == app.identity else { return false }
            var removed = app
            removed.classification = .block
            removed.removed = true
            agent.stubbedApplicationRegistry = .init(applications: [removed])
            return true
        }
        let model = ApplicationSettingsModel(agent: agent)
        await model.load()
        model.selection = app.id
        await model.removeSelected()
        #expect(model.applications.isEmpty)
        #expect(model.selection == nil)
        #expect(model.snapshot?.applications.first?.classification == .block)
    }

    @Test func acceptedButUnrefreshableChangeReportsUncertainty() async throws {
        let agent = MockAgentController()
        let app = try application()
        agent.stubbedApplicationRegistry = .init(applications: [app])
        agent.applicationPolicyHandler = { _ in agent.stubbedApplicationRegistry = nil; return true }
        let model = ApplicationSettingsModel(agent: agent)
        await model.load()
        await model.classify(app, as: .block)
        #expect(model.message?.contains("accepted the change") == true)
        #expect(model.applications.first?.classification == .bot)
        #expect(!model.isBusy)
    }

    @Test func sameClassificationDoesNotRequestAuthenticationAgain() async throws {
        let agent = MockAgentController()
        let app = try application()
        agent.stubbedApplicationRegistry = .init(applications: [app])
        let model = ApplicationSettingsModel(agent: agent)
        await model.load()
        await model.classify(app, as: .bot)
        #expect(agent.applicationPolicyChanges.isEmpty)
    }
}
