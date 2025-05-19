//
//  TransmitView.swift
//  Rendezvous
//
//  Created by Nora Trapp on 3/26/25.
//

import SwiftUI
import CryptoKit

struct TransmitView: View {
    let credentials: [Credential]
    let onAbort: () -> Void

    init(credentials: [Credential], onAbort: @escaping () -> Void) {
        self.credentials = credentials
        self.onAbort = onAbort
    }

    enum FocusedField {
        case disclosure
    }
    
    enum ContentState {
        case confirmation
        case disclosure
    }
    
    enum DisclosureState {
        case awaiting
        case submitting
        case submitted
    }
    
    enum ErrorSheetState: Equatable {
        case hidden
        case visible(String)
    }
    
    @State private var contentState: ContentState = .confirmation {
        didSet {
            disclosureState = .awaiting
            disclosureText = Self.disclosurePrompt
        }
    }
    @State private var disclosureState: DisclosureState = .awaiting
    @State private var errorState: ErrorSheetState = .hidden
    @FocusState private var focusState: FocusedField?
    
    @State private var recipients: [Recipient] = []
    @State private var selectedRecipient: Recipient?
    @State private var isLoadingRecipients = false
    @State private var showRecipientPopover = false
    
    @State private var fromText: String = "anonymous"

    static let disclosurePrompt = "> "
    @State private var disclosureText = disclosurePrompt
    @State private var timeRemaining: TimeInterval = 0
    @State private var timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        let disclosureTextBinding = Binding<String>(get: {
            disclosureText
        }, set: {
            disclosureText = $0
            if $0 != Self.disclosurePrompt {
                disclosureState = .awaiting
            }
        })
        
        let isErrorSheetVisible = Binding<Bool>(get: { errorState != .hidden }, set: { _ in })
        
        return ZStack {
            switch contentState {
            case .confirmation:
                VStack(spacing: 20) {
                    Spacer()
                    
                    Text("We found \"\(credentials.commonOrganization!)\" as your organization.")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.green)
                        .padding()

                    Button("[ CONTINUE ]") {
                        contentState = .disclosure
                        timeRemaining = credentials.soonestExpiration!.timeIntervalSinceNow
                    }
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundStyle(.green)

                    Button("[ ABORT ]") { onAbort() }
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundStyle(.red)
                    
                    Spacer()
                }
                .padding()
            case .disclosure:
                ScrollView {
                    VStack(spacing: 20) {
                        VStack(spacing: 10) {
                            Text("ORG: \(credentials.commonOrganization!)")
                                .font(.system(.headline, design: .monospaced))
                                .foregroundStyle(.green)

                            Text("EXP: \(format(time: timeRemaining))")
                                .font(.system(.subheadline, design: .monospaced))
                                .foregroundStyle(.green.opacity(0.8))
                                .onReceive(timer) { _ in
                                    if timeRemaining > 0 {
                                        timeRemaining -= 1
                                    }
                                }

                            Button("[ ERASE ]") { onAbort() }
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.bold)
                            .foregroundStyle(.red)
                        }

                        Divider().background(Color.green)

                        VStack(alignment: .leading, spacing: 10) {
                            Text("BEGIN DISCLOSURE")
                                .font(.system(.title2, design: .monospaced))
                                .foregroundStyle(.green)
                            
                            if isLoadingRecipients {
                                ProgressView("Loading recipients…")
                                    .font(.system(.title2, design: .monospaced))
                            } else if recipients.isEmpty {
                                Text("No recipients available")
                                    .font(.system(.title2, design: .monospaced))
                                    .foregroundColor(.red)
                            } else {
                                HStack(alignment: .top) {
                                    Text("FROM: ")
                                        .font(.system(.headline, design: .monospaced))
                                        .foregroundStyle(.green)

                                    TextField("anonymous", text: $fromText)
                                        .font(.system(.body, design: .monospaced))
                                        .foregroundStyle(.green)
                                        .accentColor(.green)
                                }
                                
                                HStack(alignment: .top) {
                                    Text("TO: ")
                                        .font(.system(.headline, design: .monospaced))
                                        .foregroundStyle(.green)
                                    Menu {
                                        ForEach(recipients, id: \.publicKey.rawRepresentation) { recipient in
                                            Button(action: {
                                                selectedRecipient = recipient
                                            }) {
                                                Text(recipient.name)
                                                Text(recipient.publicKey.rawRepresentation.base64EncodedString())
                                            }
                                        }
                                    } label: {
                                        HStack {
                                            Text("▼ \(selectedRecipient?.name ?? "SELECT")")
                                                .font(.system(.headline, design: .monospaced))
                                                .foregroundStyle(.green)
                                        }
                                    }.onTapGesture {
                                        fetchRecipients()
                                    }
                                    if let selectedRecipient = selectedRecipient {
                                        Button(action: {
                                            showRecipientPopover.toggle()
                                        }) {
                                            Image(systemName: "lock")
                                                .foregroundStyle(.green)
                                        }
                                        .buttonStyle(.plain)
                                        .popover(
                                            isPresented: $showRecipientPopover
                                        ) {
                                            VStack(alignment: .leading, spacing: 10) {
                                                Text("PUBLIC KEY:")
                                                    .font(.system(.headline, design: .monospaced))
                                                    .foregroundStyle(.green)
                                                
                                                Text(selectedRecipient.publicKey.urlSafeBase64EncodedString())
                                                    .font(.system(.footnote, design: .monospaced))
                                                    .foregroundStyle(.green)
                                            }
                                            .padding()
                                            .preferredColorScheme(.dark)
                                            .presentationCompactAdaptation(.popover)
                                        }
                                    }
                                }

                            }

                            ZStack(alignment: .topLeading) {
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color.green)

                                VStack(alignment: .leading) {
                                    ScrollView {
                                        VStack(alignment: .leading, spacing: 4) {
                                            HStack(alignment: .top, spacing: 4) {
                                                Text("")
                                                    .foregroundStyle(.green)
                                                    .font(.system(.body, design: .monospaced))
                                                TextField("Enter your report...", text: disclosureTextBinding, axis: .vertical)
                                                    .font(.system(.body, design: .monospaced))
                                                    .foregroundStyle(.green)
                                                    .accentColor(.green)
                                                    .focused($focusState, equals: .disclosure)
                                            }
                                        }
                                        .padding(8)
                                    }
                                    .frame(minHeight: 200)
                                }
                            }
                            
                            

                            Button {
                                submitDisclosure(credentials: credentials)
                            }
                            label: {
                                switch disclosureState {
                                case .submitting:
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: .green))
                                        .frame(maxWidth: .infinity)
                                case .awaiting, .submitted:
                                    Text("[ TRANSMIT ]")
                                        .font(.system(.body, design: .monospaced))
                                        .fontWeight(.bold)
                                        .frame(maxWidth: .infinity)
                                }
                            }
                                .foregroundStyle(.green)

                            if disclosureState == .submitted {
                                Text("Transmission Successful")
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundStyle(.green)
                                    .padding(.top)
                            }
                        }
                    }
                    .padding()
                }
            }
        }
        .actionSheet(isPresented: isErrorSheetVisible) {
            guard case let .visible(errorMessage) = errorState else { return ActionSheet(title: Text("")) }
            
            return ActionSheet(
                title: Text(errorMessage),
                buttons: [
                    ActionSheet.Button.default(Text("OK")) { errorState = .hidden }
                ]
            )
        }
        .onAppear {
            focusState = .disclosure
            fetchRecipients()
        }
    }
    
    func fetchRecipients() {
        isLoadingRecipients = true
        RendezvousPoint.all.requestCommonRecipients { recipients in
            DispatchQueue.main.async {
                self.isLoadingRecipients = false
                self.recipients = recipients
                self.selectedRecipient = recipients.first
            }
        }
    }
    
    func submitDisclosure(credentials: [Credential]) {
        disclosureState = .submitting
        
        do {
            try credentials.submitDisclosure(
                .init(text: disclosureText, author: fromText),
                recipient: selectedRecipient!
            ) { success in
                DispatchQueue.main.async {
                    guard success else {
                        disclosureState = .awaiting
                        errorState = .visible("Failed to submit disclosure, please try again")
                        return
                    }
                    
                    disclosureState = .submitted
                    disclosureText = Self.disclosurePrompt
                }
            }
        } catch {
            disclosureState = .awaiting
            errorState = .visible("Failed to submit disclosure, please try again")
        }
    }

    func format(time: TimeInterval) -> String {
        let seconds = Int(time) % 60
        let minutes = (Int(time) / 60) % 60
        let hours = (Int(time) / 3600) % 24
        let days = Int(time) / 86400

        var components: [String] = []
        if days > 0 { components.append("\(days)d") }
        if hours > 0 { components.append("\(hours)h") }
        if minutes > 0 { components.append("\(minutes)m") }
        components.append("\(seconds)s")

        return components.joined(separator: " ")
    }
}
