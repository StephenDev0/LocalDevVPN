//
//  ContentView.swift
//  LocalDevVPN
//
//  Created by Stossy11 on 28/03/2025.
//

import Foundation
import NetworkExtension
import Security
import SwiftUI

import NavigationBackport

extension Bundle {
    var shortVersion: String { object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0" }
}

// MARK: - Logging Utility

class VPNLogger: ObservableObject {
    @Published var logs: [String] = []

    static var shared = VPNLogger()

    private init() {}

    func log(_ message: Any, file: String = #file, function: String = #function, line: Int = #line) {
        #if DEBUG
            let fileName = (file as NSString).lastPathComponent
            print("[\(fileName):\(line)] \(function): \(message)")
        #endif

        logs.append("\(message)")
    }
}

// MARK: - Tunnel Manager

class TunnelManager: ObservableObject {
    @Published var hasLocalDeviceSupport = false
    @Published var tunnelStatus: TunnelStatus = .disconnected

    static var shared = TunnelManager()

    @Published var waitingOnSettings: Bool = false
    private var vpnObserver: NSObjectProtocol?
    private let isSimulator: Bool = {
        #if targetEnvironment(simulator)
            return true
        #else
            return false
        #endif
    }()

    var serverAddress: String {
        UserDefaults.standard.string(forKey: "VPNServerAddress") ?? ""
    }

    var remoteIdentifier: String {
        UserDefaults.standard.string(forKey: "VPNRemoteIdentifier") ?? ""
    }

    enum TunnelStatus {
        case disconnected
        case connecting
        case connected
        case disconnecting
        case error

        var color: Color {
            switch self {
            case .disconnected: return .gray
            case .connecting: return .orange
            case .connected: return .green
            case .disconnecting: return .orange
            case .error: return .red
            }
        }

        var systemImage: String {
            switch self {
            case .disconnected: return "network.slash"
            case .connecting: return "network.badge.shield.half.filled"
            case .connected: return "checkmark.shield.fill"
            case .disconnecting: return "network.badge.shield.half.filled"
            case .error: return "exclamationmark.shield.fill"
            }
        }

        var localizedTitle: LocalizedStringKey {
            switch self {
            case .disconnected:
                return "disconnected"
            case .connecting:
                return "connecting"
            case .connected:
                return "connected"
            case .disconnecting:
                return "disconnecting"
            case .error:
                return "error"
            }
        }
    }

    private init() {
        if isSimulator {
            VPNLogger.shared.log("Running on Simulator – VPN calls are mocked")
            DispatchQueue.main.async { [weak self] in
                self?.waitingOnSettings = true
            }
        } else {
            setupStatusObserver()
            loadVPNPreferences()
        }
    }

    // MARK: - Private Methods

    private func loadVPNPreferences() {
        NEVPNManager.shared().loadFromPreferences { [weak self] error in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if let error = error {
                    VPNLogger.shared.log("Error loading VPN preferences: \(error.localizedDescription)")
                }
                self.hasLocalDeviceSupport = true
                self.waitingOnSettings = true
                self.updateTunnelStatus(from: NEVPNManager.shared().connection.status)
            }
        }
    }

    private func setupStatusObserver() {
        vpnObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let self = self,
                  let connection = notification.object as? NEVPNConnection else { return }
            VPNLogger.shared.log("VPN Status notification received: \(connection.status.rawValue)")
            self.updateTunnelStatus(from: connection.status)
        }
    }

    private func updateTunnelStatus(from connectionStatus: NEVPNStatus) {
        let newStatus: TunnelStatus
        switch connectionStatus {
        case .invalid, .disconnected:
            newStatus = .disconnected
        case .connecting:
            newStatus = .connecting
        case .connected:
            newStatus = .connected
        case .disconnecting:
            newStatus = .disconnecting
        case .reasserting:
            newStatus = .connecting
        @unknown default:
            newStatus = .error
        }

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if self.tunnelStatus != newStatus {
                VPNLogger.shared.log("LocalDevVPN status updated from \(self.tunnelStatus) to \(newStatus)")
            }
            self.tunnelStatus = newStatus
        }
    }

    private func configureAndStartVPN() {
        let manager = NEVPNManager.shared()
        let proto = NEVPNProtocolIKEv2()
        proto.serverAddress = serverAddress
        proto.remoteIdentifier = remoteIdentifier.isEmpty ? serverAddress : remoteIdentifier
        proto.authenticationMethod = .sharedSecret
        proto.useExtendedAuthentication = false
        proto.disconnectOnSleep = false
        proto.sharedSecretReference = getOrCreateSharedSecretRef()

        manager.protocolConfiguration = proto
        manager.localizedDescription = "LocalDevVPN"
        manager.isEnabled = true

        manager.saveToPreferences { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                VPNLogger.shared.log("Error saving VPN configuration: \(error.localizedDescription)")
                DispatchQueue.main.async { self.tunnelStatus = .error }
                return
            }
            manager.loadFromPreferences { [weak self] _ in
                guard let self = self else { return }
                do {
                    try manager.connection.startVPNTunnel()
                    VPNLogger.shared.log("LocalDevVPN tunnel start initiated")
                } catch {
                    VPNLogger.shared.log("Failed to start LocalDevVPN tunnel: \(error.localizedDescription)")
                    DispatchQueue.main.async { self.tunnelStatus = .error }
                }
            }
        }
    }

    // MARK: - Keychain Helpers

    private func getOrCreateSharedSecretRef() -> Data? {
        let service = Bundle.main.bundleIdentifier ?? "com.jkcoxson.LocalDevVPN"
        let account = "vpn-shared-secret"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnPersistentRef as String: true,
        ]
        var result: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess {
            return result as? Data
        }
        return saveSharedSecret("localdevvpn".data(using: .utf8)!)
    }

    func saveSharedSecret(_ secretData: Data) -> Data? {
        let service = Bundle.main.bundleIdentifier ?? "com.jkcoxson.LocalDevVPN"
        let account = "vpn-shared-secret"
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: secretData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecReturnPersistentRef as String: true,
        ]
        var result: AnyObject?
        let status = SecItemAdd(addQuery as CFDictionary, &result)
        return status == errSecSuccess ? result as? Data : nil
    }

    // MARK: - Public Methods

    func toggleVPNConnection() {
        if tunnelStatus == .connected || tunnelStatus == .connecting {
            stopVPN()
        } else {
            startVPN()
        }
    }

    func startVPN() {
        if isSimulator {
            simulateStartVPN()
            return
        }

        let currentStatus = NEVPNManager.shared().connection.status
        if currentStatus == .connected {
            VPNLogger.shared.log("VPN already connected, updating UI")
            DispatchQueue.main.async { [weak self] in self?.tunnelStatus = .connected }
            return
        }
        if currentStatus == .connecting {
            VPNLogger.shared.log("VPN already connecting, updating UI")
            DispatchQueue.main.async { [weak self] in self?.tunnelStatus = .connecting }
            return
        }

        configureAndStartVPN()
    }

    func stopVPN() {
        if isSimulator {
            simulateStopVPN()
            return
        }

        DispatchQueue.main.async { [weak self] in
            self?.tunnelStatus = .disconnecting
        }

        NEVPNManager.shared().connection.stopVPNTunnel()
        VPNLogger.shared.log("LocalDevVPN tunnel stop initiated")
    }

    func handleVPNStatusChange(notification: Notification) {
        guard let connection = notification.object as? NEVPNConnection else { return }
        VPNLogger.shared.log("Handling VPN status change: \(connection.status.rawValue)")
        updateTunnelStatus(from: connection.status)
    }

    // MARK: - Cleanup Utilities

    func cleanupAllVPNConfigurations() {
        if isSimulator {
            VPNLogger.shared.log("Simulator cleanup skipped – no real VPN configurations to remove")
            return
        }

        NEVPNManager.shared().loadFromPreferences { [weak self] _ in
            NEVPNManager.shared().connection.stopVPNTunnel()
            NEVPNManager.shared().removeFromPreferences { error in
                if let error = error {
                    VPNLogger.shared.log("Error removing VPN configuration: \(error.localizedDescription)")
                } else {
                    VPNLogger.shared.log("Successfully removed VPN configuration")
                }
                DispatchQueue.main.async { [weak self] in
                    self?.tunnelStatus = .disconnected
                }
            }
        }
    }

    deinit {
        if let observer = vpnObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    private func simulateStartVPN() {
        VPNLogger.shared.log("Simulator: pretend to start VPN")
        DispatchQueue.main.async { [weak self] in
            self?.tunnelStatus = .connecting
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
            self?.tunnelStatus = .connected
            VPNLogger.shared.log("Simulator: VPN marked connected")
        }
    }

    private func simulateStopVPN() {
        VPNLogger.shared.log("Simulator: pretend to stop VPN")
        DispatchQueue.main.async { [weak self] in
            self?.tunnelStatus = .disconnecting
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            self?.tunnelStatus = .disconnected
            VPNLogger.shared.log("Simulator: VPN marked disconnected")
        }
    }
}

// MARK: - Views

struct ContentView: View {
    @StateObject private var tunnelManager = TunnelManager.shared
    @State private var showSettings = false
    @State var tunnel = false
    @AppStorage("autoConnect") private var autoConnect = false
    @AppStorage("hasNotCompletedSetup") private var hasNotCompletedSetup = true
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        NBNavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    TitleWithSettingsRow(showSettings: $showSettings)

                    StatusOverviewCard()

                    ConnectivityControlsCard(
                        action: {
                            tunnelManager.tunnelStatus == .connected ? tunnelManager.stopVPN() : tunnelManager.startVPN()
                        }
                    )

                    if tunnelManager.tunnelStatus == .connected {
                        ConnectionStatsView()
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 12)
                .frame(maxWidth: .infinity, alignment: .top)
            }
            .applyAdaptiveBounce()
            .background(backgroundColor.ignoresSafeArea())
            .navigationTitle("")
            #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
            #endif
            .tvOSNavigationBarTitleDisplayMode(.inline)
            .onChange(of: tunnelManager.waitingOnSettings) { finished in
                if tunnelManager.tunnelStatus != .connected && autoConnect && finished {
                    tunnelManager.startVPN()
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
            .sheet(isPresented: $hasNotCompletedSetup) {
                SetupView()
            }
        }
    }

    private var backgroundColor: Color {
        if colorScheme == .dark {
            return Color(.systemBackground)
        } else {
            return Color(.systemGroupedBackground)
        }
    }
}

struct TitleWithSettingsRow: View {
    @Binding var showSettings: Bool

    var body: some View {
        HStack(spacing: 10) {
            Text("LocalDevVPN")
                .font(.largeTitle)
                .fontWeight(.bold)
                .accessibilityAddTraits(.isHeader)

            Spacer()

            Button {
                showSettings = true
            } label: {
                Image(systemName: "gear")
                    .font(.title2.weight(.semibold))
                    .foregroundColor(.primary)
            }
            .accessibilityLabel(Text("settings"))
        }
        .padding(.top, 4)
    }
}

extension View {
    @ViewBuilder
    func tvOSNavigationBarTitleDisplayMode(_ displayMode: NavigationBarItem.TitleDisplayMode) -> some View {
        #if os(iOS)
            navigationBarTitleDisplayMode(displayMode)
        #else
            self
        #endif
    }

    @ViewBuilder
    func applyAdaptiveBounce() -> some View {
        if #available(iOS 16.4, tvOS 16.4, *) {
            scrollBounceBehavior(.basedOnSize)
        } else {
            self
        }
    }
}

struct StatusOverviewCard: View {
    @StateObject private var tunnelManager = TunnelManager.shared
    @AppStorage("VPNServerAddress") private var serverAddress = ""

    var body: some View {
        DashboardCard {
            VStack(alignment: .leading, spacing: 18) {
                Text("current_status")
                    .font(.headline)

                HStack(spacing: 18) {
                    StatusGlyphView()

                    Text(tunnelManager.tunnelStatus.localizedTitle)
                        .font(.title3)
                        .fontWeight(.semibold)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity, alignment: .center)
                }

                Divider()

                HStack {
                    Label {
                        Text(statusTip)
                    } icon: {
                        Image(systemName: "info.circle")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)

                    Spacer()

                    HStack(spacing: 4) {
                        Text("connected_at")
                        Text(Date(), style: .time)
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
            }
        }
    }

    private var statusTip: String {
        switch tunnelManager.tunnelStatus {
        case .connected:
            return String(format: NSLocalizedString("connected_to_ip", comment: ""), serverAddress.isEmpty ? "server" : serverAddress)
        case .connecting:
            return NSLocalizedString("ios_might_ask_you_to_allow_the_vpn", comment: "")
        case .disconnecting:
            return NSLocalizedString("disconnecting_safely", comment: "")
        case .error:
            return NSLocalizedString("open_settings_to_review_details", comment: "")
        default:
            return NSLocalizedString("tap_connect_to_create_the_tunnel", comment: "")
        }
    }
}

struct StatusGlyphView: View {
    @StateObject private var tunnelManager = TunnelManager.shared
    @State private var ringScale: CGFloat = 1.0

    var body: some View {
        ZStack {
            Circle()
                .stroke(tunnelManager.tunnelStatus.color.opacity(0.25), lineWidth: 6)
                .scaleEffect(ringScale, anchor: .center)
                .animation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true), value: ringScale)

            Circle()
                .fill(tunnelManager.tunnelStatus.color.opacity(0.15))

            Image(systemName: tunnelManager.tunnelStatus.systemImage)
                .font(.title)
                .foregroundColor(tunnelManager.tunnelStatus.color)
        }
        .frame(width: 92, height: 92)
        .onAppear(perform: startPulse)
    }

    private func startPulse() {
        DispatchQueue.main.async {
            ringScale = 1.08
        }
    }
}

struct ConnectivityControlsCard: View {
    let action: () -> Void

    var body: some View {
        DashboardCard {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("connection")
                        .font(.headline)
                    Text("start_or_stop_the_secure_local_tunnel")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                ConnectionButton(action: action)
            }
        }
    }
}

struct ConnectionInfoRow: View {
    let title: LocalizedStringKey
    let value: String
    let icon: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.body)
                .foregroundColor(.accentColor)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(value)
                    .font(.body)
                    .foregroundColor(.primary)
            }
            Spacer()
        }
    }
}

struct ConnectionButton: View {
    @StateObject private var tunnelManager = TunnelManager.shared
    let action: () -> Void
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Button(action: action) {
            HStack {
                Text(buttonText)
                    .font(.headline)
                    .fontWeight(.semibold)

                if tunnelManager.tunnelStatus == .connecting || tunnelManager.tunnelStatus == .disconnecting {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .padding(.leading, 5)
                }
            }
            .frame(maxWidth: .infinity)
            .frame(height: 56)
            .background(buttonBackground)
            .foregroundColor(.white)
            .clipShape(Capsule())
            .shadow(color: shadowColor, radius: 10, x: 0, y: 5)
        }
        .disabled(tunnelManager.tunnelStatus == .connecting || tunnelManager.tunnelStatus == .disconnecting)
    }

    private var buttonText: String {
        switch tunnelManager.tunnelStatus {
        case .connected:
            return NSLocalizedString("disconnect", comment: "")
        case .connecting:
            return NSLocalizedString("connecting_ellipsis", comment: "")
        case .disconnecting:
            return NSLocalizedString("disconnecting_ellipsis", comment: "")
        default:
            return NSLocalizedString("connect", comment: "")
        }
    }

    private var buttonBackground: some View {
        Group {
            if tunnelManager.tunnelStatus == .connected {
                LinearGradient(
                    gradient: Gradient(colors: [Color.red.opacity(0.8), Color.red]),
                    startPoint: .leading,
                    endPoint: .trailing
                )
            } else {
                LinearGradient(
                    gradient: Gradient(colors: [Color.blue.opacity(0.8), Color.blue]),
                    startPoint: .leading,
                    endPoint: .trailing
                )
            }
        }
    }

    private var shadowColor: Color {
        colorScheme == .dark ? Color.black.opacity(0.5) : Color.black.opacity(0.15)
    }
}

struct ConnectionStatsView: View {
    @StateObject private var tunnelManager = TunnelManager.shared
    @AppStorage("VPNServerAddress") private var serverAddress = ""
    @AppStorage("VPNRemoteIdentifier") private var remoteIdentifier = ""

    var body: some View {
        DashboardCard {
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("session_details")
                        .font(.headline)
                    Text("live_stats_while_the_tunnel_is_connected")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                Divider()

                Text("network_configuration")
                    .font(.caption)
                    .foregroundColor(.secondary)

                ConnectionInfoRow(
                    title: "Server Address",
                    value: serverAddress.isEmpty ? "—" : serverAddress,
                    icon: "server.rack"
                )

                ConnectionInfoRow(
                    title: "Remote ID",
                    value: remoteIdentifier.isEmpty ? (serverAddress.isEmpty ? "—" : serverAddress) : remoteIdentifier,
                    icon: "point.3.filled.connected.trianglepath.dotted"
                )
            }
        }
    }

}

struct StatItemView: View {
    let title: LocalizedStringKey
    let value: String
    let icon: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .foregroundColor(.accentColor)
                    .font(.caption)
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Text(value)
                .font(.headline)
                .foregroundColor(.primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct DashboardCard<Content: View>: View {
    private let content: () -> Content
    @Environment(\.colorScheme) private var colorScheme

    init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    var body: some View {
        content()
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(Color(.secondarySystemBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .stroke(borderColor)
            )
            .shadow(color: shadowColor, radius: 12, x: 0, y: 6)
    }

    private var borderColor: Color {
        colorScheme == .dark ? Color.white.opacity(0.08) : Color.black.opacity(0.06)
    }

    private var shadowColor: Color {
        colorScheme == .dark ? Color.black.opacity(0.5) : Color.black.opacity(0.12)
    }
}

// MARK: - Updated SettingsView

struct SettingsView: View {
    @Environment(\.presentationMode) var presentationMode
    @AppStorage("selectedLanguage") private var selectedLanguage = Locale.current.languageCode ?? "en"
    @AppStorage("VPNServerAddress") private var serverAddress = ""
    @AppStorage("VPNRemoteIdentifier") private var remoteIdentifier = ""
    @AppStorage("autoConnect") private var autoConnect = false
    @StateObject private var tunnelManager = TunnelManager.shared
    @AppStorage("hasNotCompletedSetup") private var hasNotCompletedSetup = true

    @State private var sharedSecret = ""
    @State private var showRestartPopUp = false

    var body: some View {
        NBNavigationStack {
            List {
                Section(header: Text("connection_settings")) {
                    Toggle("auto_connect_on_launch", isOn: $autoConnect)
                    NavigationLink(destination: ConnectionLogView()) {
                        Label("connection_logs", systemImage: "doc.text")
                    }
                }

                Section(header: Text("network_configuration")) {
                    Group {
                        networkConfigRow(label: "Server Address", text: $serverAddress)
                        networkConfigRow(label: "Remote Identifier", text: $remoteIdentifier)
                        HStack {
                            Text("Shared Secret")
                            Spacer()
                            SecureField("secret", text: $sharedSecret)
                                .multilineTextAlignment(.trailing)
                                .foregroundColor(.secondary)
                                .onChange(of: sharedSecret) { newValue in
                                    if !newValue.isEmpty, let data = newValue.data(using: .utf8) {
                                        _ = tunnelManager.saveSharedSecret(data)
                                    }
                                }
                        }
                    }
                }

                Section(header: Text("app_information")) {
                    Button {
                        UIApplication.shared.open(URL(string: "https://jkcoxson.com/cdn/LocalDevVPN/LocalDevVPNPrivacyPolicy.md")!, options: [:])
                    } label: {
                        Label("privacy_policy", systemImage: "lock.shield")
                    }
                    NavigationLink(destination: DataCollectionInfoView()) {
                        Label("data_collection_policy", systemImage: "hand.raised.slash")
                    }
                    HStack {
                        Text("app_version")
                        Spacer()
                        Text(Bundle.main.shortVersion)
                            .foregroundColor(.secondary)
                    }
                    NavigationLink(destination: HelpView()) {
                        Text("help_and_support")
                    }
                }

                Section(header: Text("language")) {
                    Picker("dropdown_language", selection: $selectedLanguage) {
                        Text("english").tag("en")
                        Text("spanish").tag("es")
                        Text("italian").tag("it")
                        Text("polish").tag("pl")
                        Text("korean").tag("ko")
                        Text("TChinese").tag("zh-Hant")
                        Text("french").tag("fr")
                    }
                    .onChange(of: selectedLanguage) { newValue in
                        let languageCode = newValue
                        LanguageManager.shared.updateLanguage(to: languageCode)
                        showRestartPopUp = true
                    }
                    .alert(isPresented: $showRestartPopUp) {
                        Alert(
                            title: Text("restart_title"),
                            message: Text("restart_message"),
                            dismissButton: .cancel(Text("understand_button")) {
                                showRestartPopUp = true
                            }
                        )
                    }
                }
            }
            .navigationTitle(Text("settings"))
            .tvOSNavigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("done") {
                        dismiss()
                    }
                }
            }
        }
    }

    private func dismiss() {
        presentationMode.wrappedValue.dismiss()
    }

    private func networkConfigRow(label: LocalizedStringKey, text: Binding<String>) -> some View {
        HStack {
            Text(label)
            Spacer()
            TextField(label, text: text)
                .multilineTextAlignment(.trailing)
                .foregroundColor(.secondary)
                .keyboardType(.URL)
                .autocapitalization(.none)
        }
    }
}

// MARK: - New Data Collection Info View

struct DataCollectionInfoView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("data_collection_policy_title")
                    .font(.title)
                    .fontWeight(.bold)
                    .padding(.bottom, 10)

                GroupBox(label: Label("no_data_collection", systemImage: "hand.raised.slash").font(.headline)) {
                    Text("no_data_collection_description")
                        .padding(.vertical)
                }

                GroupBox(label: Label("local_processing_only", systemImage: "iphone").font(.headline)) {
                    Text("local_processing_only_description")
                        .padding(.vertical)
                }

                GroupBox(label: Label("no_third_party_sharing", systemImage: "person.2.slash").font(.headline)) {
                    Text("no_third_party_sharing_description")
                        .padding(.vertical)
                }

                GroupBox(label: Label("why_use_network_permissions", systemImage: "network").font(.headline)) {
                    Text("why_use_network_permissions_description")
                        .padding(.vertical)
                }

                GroupBox(label: Label("our_promise", systemImage: "checkmark.seal").font(.headline)) {
                    Text("our_promise_description")
                        .padding(.vertical)
                }
            }
            .padding()
        }
        .navigationTitle(Text("data_collection_policy_nav"))
        .tvOSNavigationBarTitleDisplayMode(.inline)
    }
}

struct ConnectionLogView: View {
    @StateObject var logger = VPNLogger.shared
    var body: some View {
        List(logger.logs, id: \.self) { log in
            Text(log)
                .font(.system(.body, design: .monospaced))
        }
        .navigationTitle(Text("logs_nav"))
        .tvOSNavigationBarTitleDisplayMode(.inline)
    }
}

struct HelpView: View {
    var body: some View {
        List {
            Section(header: Text("faq_header")) {
                NavigationLink("faq_q1") {
                    VStack(alignment: .leading, spacing: 15) {
                        Text("faq_q1_a1")
                            .padding(.bottom, 10)
                        Text("faq_common_use_cases")
                            .fontWeight(.medium)
                        Text("faq_case1")
                        Text("faq_case2")
                        Text("faq_case3")
                        Text("faq_case4")
                    }
                    .padding()
                }
                NavigationLink("faq_q2") {
                    VStack(alignment: .leading, spacing: 15) {
                        Text("faq_q2_a1")
                            .padding(.bottom, 10)
                            .font(.headline)
                        Text("faq_q2_point1")
                        Text("faq_q2_point2")
                        Text("faq_q2_point3")
                        Text("faq_q2_point4")
                        Text("faq_q2_a2")
                            .padding(.top, 10)
                    }
                    .padding()
                }
                NavigationLink("faq_q3") {
                    VStack(alignment: .leading, spacing: 15) {
                        Text("faq_q3_a1")
                            .padding(.bottom, 10)
                        Text("faq_troubleshoot_header")
                            .font(.headline)
                        Text("faq_troubleshoot1")
                        Text("faq_troubleshoot2")
                        Text("faq_troubleshoot3")
                        Text("faq_troubleshoot4")
                    }
                    .padding()
                }
                NavigationLink("faq_q4") {
                    VStack(alignment: .leading, spacing: 15) {
                        Text("faq_q4_intro")
                            .font(.headline)
                            .padding(.bottom, 10)
                        Text("faq_q4_case1")
                        Text("faq_q4_case2")
                        Text("faq_q4_case3")
                        Text("faq_q4_case4")
                        Text("faq_q4_conclusion")
                            .padding(.top, 10)
                    }
                    .padding()
                }
            }
            Section(header: Text("business_model_header")) {
                NavigationLink("biz_q1") {
                    VStack(alignment: .leading, spacing: 15) {
                        Text("biz_q1_a1")
                            .padding(.bottom, 10)
                        Text("biz_key_points_header")
                            .font(.headline)
                        Text("biz_point1")
                        Text("biz_point2")
                        Text("biz_point3")
                        Text("biz_point4")
                        Text("biz_point5")
                    }
                    .padding()
                }
            }
            Section(header: Text("app_info_header")) {
                HStack {
                    Image(systemName: "exclamationmark.shield")
                    Text("requires_ios")
                }
                HStack {
                    Image(systemName: "lock.shield")
                    Text("uses_network_extension")
                }
            }
        }
        .navigationTitle(Text("help_and_support_nav"))
        .tvOSNavigationBarTitleDisplayMode(.inline)
    }
}

struct SetupView: View {
    @Environment(\.presentationMode) var presentationMode
    @AppStorage("hasNotCompletedSetup") private var hasNotCompletedSetup = true
    @State private var currentPage = 0
    let pages = [
        SetupPage(
            title: "setup_welcome_title",
            description: "setup_welcome_description",
            imageName: "checkmark.shield.fill",
            details: "setup_welcome_details"
        ),
        SetupPage(
            title: "setup_why_title",
            description: "setup_why_description",
            imageName: "person.2.fill",
            details: "setup_why_details"
        ),
        SetupPage(
            title: "setup_easy_title",
            description: "setup_easy_description",
            imageName: "hand.tap.fill",
            details: "setup_easy_details"
        ),
        SetupPage(
            title: "setup_privacy_title",
            description: "setup_privacy_description",
            imageName: "lock.shield.fill",
            details: "setup_privacy_details"
        ),
    ]
    var body: some View {
        NBNavigationStack {
            VStack {
                TabView(selection: $currentPage) {
                    ForEach(0 ..< pages.count, id: \.self) { index in
                        SetupPageView(page: pages[index])
                            .tag(index)
                    }
                }
                .tabViewStyle(PageTabViewStyle(indexDisplayMode: .always))
                Spacer()
                if currentPage == pages.count - 1 {
                    Button {
                        hasNotCompletedSetup = false
                        dismiss()
                    } label: {
                        Text("setup_get_started")
                            .font(.headline)
                            .fontWeight(.semibold)
                            .frame(height: 50)
                            .frame(maxWidth: .infinity)
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(10)
                            .padding(.horizontal)
                    }
                    .padding(.bottom)
                } else {
                    Button {
                        withAnimation { currentPage += 1 }
                    } label: {
                        Text("setup_next")
                            .font(.headline)
                            .fontWeight(.semibold)
                            .frame(height: 50)
                            .frame(maxWidth: .infinity)
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(10)
                            .padding(.horizontal)
                    }
                    .padding(.bottom)
                }
            }
            .navigationTitle(Text("setup_nav"))
            .tvOSNavigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("setup_skip") { hasNotCompletedSetup = false; dismiss() }
                }
            }
        }
    }

    private func dismiss() {
        presentationMode.wrappedValue.dismiss()
    }
}

struct SetupPage {
    let title: LocalizedStringKey
    let description: LocalizedStringKey
    let imageName: String
    let details: LocalizedStringKey
}

struct SetupPageView: View {
    let page: SetupPage

    var body: some View {
        VStack(spacing: tvOSSpacing) {
            Image(systemName: page.imageName)
                .font(.system(size: tvOSImageSize))
                .foregroundColor(.blue)
                .padding(.top, tvOSTopPadding)

            Text(page.title)
                .font(tvOSTitleFont)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)

            Text(page.description)
                .font(tvOSDescriptionFont)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            ScrollView {
                Text(page.details)
                    .font(tvOSBodyFont)
                    .multilineTextAlignment(.leading)
                    .padding(.horizontal)
            }

            Spacer()
        }
        .padding()
    }

    // MARK: - Conditional sizes for tvOS

    private var tvOSImageSize: CGFloat {
        #if os(tvOS)
            return 60
        #else
            return 80
        #endif
    }

    private var tvOSTopPadding: CGFloat {
        #if os(tvOS)
            return 30
        #else
            return 50
        #endif
    }

    private var tvOSSpacing: CGFloat {
        #if os(tvOS)
            return 20
        #else
            return 30
        #endif
    }

    private var tvOSTitleFont: Font {
        #if os(tvOS)
            return .headline // .system(size: 35).bold()
        #else
            return .title
        #endif
    }

    private var tvOSDescriptionFont: Font {
        #if os(tvOS)
            return .subheadline
        #else
            return .headline
        #endif
    }

    private var tvOSBodyFont: Font {
        #if os(tvOS)
            return .system(size: 18).bold()
        #else
            return .body
        #endif
    }
}

class LanguageManager: ObservableObject {
    static let shared = LanguageManager()
    @Published var currentLanguage: String = Locale.current.languageCode ?? "en"
    private let supportedLanguages = ["en", "es", "it", "pl", "ko", "zh-Hant", "fr"]

    func updateLanguage(to languageCode: String) {
        if supportedLanguages.contains(languageCode) {
            currentLanguage = languageCode
            UserDefaults.standard.set([languageCode], forKey: "AppleLanguages")
            UserDefaults.standard.synchronize()
        } else {
            currentLanguage = "en" // FALLBACK TO DEFAULT LANGUAGE
            UserDefaults.standard.set(["en"], forKey: "AppleLanguages")
            UserDefaults.standard.synchronize()
        }
    }
}

#if os(tvOS)
    @ViewBuilder
    func GroupBox<Content: View>(
        label: some View,
        @ViewBuilder content: @escaping () -> Content
    ) -> some View {
        #if os(tvOS)
            tvOSGroupBox(label: {
                label
            }, content: content)
        #else
            SwiftUI.GroupBox(label: label, content: content)
        #endif
    }

    struct tvOSGroupBox<Label: View, Content: View>: View {
        @ViewBuilder let label: () -> Label
        @ViewBuilder let content: () -> Content

        init(
            @ViewBuilder label: @escaping () -> Label,
            @ViewBuilder content: @escaping () -> Content
        ) {
            self.label = label
            self.content = content
        }

        var body: some View {
            VStack(alignment: .leading, spacing: 8) {
                label()
                    .font(.headline)

                content()
                    .padding(.top, 4)
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(.secondary)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(.separator, lineWidth: 0.5)
            )
        }
    }
#endif

#Preview {
    ContentView()
}
