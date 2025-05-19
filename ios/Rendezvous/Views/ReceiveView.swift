//
//  ReceiveView.swift
//  Rendezvous
//
//  Created by Nora Trapp on 5/16/25.
//

import SwiftUI
import CryptoKit

struct ReceiveView: View {
    let onAbort: () -> Void

    init(onAbort: @escaping () -> Void) {
        self.onAbort = onAbort
    }
    
    enum ReceiveState {
        case register
        case inbox
    }

    enum FocusedField {
        case name
    }

    @State private var state: ReceiveState = .register
    @State private var recipientKey = Curve25519.KeyAgreement.PrivateKey()
    @State private var name: String = ""
    @State private var disclosures: [Disclosure] = []
    @State private var refreshing = false
    @State private var showOrgPopover = false

    @FocusState private var focusState: FocusedField?
    
    enum ErrorSheetState: Equatable {
        case hidden
        case visible(String)
    }
    
    @State private var errorState: ErrorSheetState = .hidden
    
    var recipient: Recipient { .init(name: name, publicKey: recipientKey.publicKey) }
    
    var body: some View {
        let isErrorSheetVisible = Binding<Bool>(get: { errorState != .hidden }, set: { _ in })

        VStack(spacing: 20) {
            switch state {
            case .register:
                VStack(alignment: .leading, spacing: 4) {
                    Text("ENTER NAME")
                        .font(.system(.title2, design: .monospaced))
                        .foregroundStyle(.green)

                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.green)

                        HStack(spacing: 4) {
                            Text(">")
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.green)

                            TextField("", text: $name)
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.green)
                                .accentColor(.green)
                                .textInputAutocapitalization(.never)
                                .disableAutocorrection(true)
                                .focused($focusState, equals: .name)
                        }
                        .padding(8)
                    }
                    .frame(height: 40)
                }

                Button("[ REGISTER ]") {
                    registerRecipient()
                }
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.green)
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)

                Button("[ ABORT ]") { onAbort() }
                    .font(.system(.body, design: .monospaced))
                    .fontWeight(.bold)
                    .foregroundStyle(.red)
                
            case .inbox:
                HStack(spacing: 10) {
                    Text("INBOX")
                        .font(.system(.title, design: .monospaced))
                        .foregroundStyle(.green)
                    
                    Button(action: {
                        showOrgPopover.toggle()
                    }) {
                        Image(systemName: "lock")
                            .foregroundStyle(.green)
                    }
                    .buttonStyle(.plain)
                    .popover(
                        isPresented: $showOrgPopover
                    ) {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("ORG: \(name)")
                                .font(.system(.headline, design: .monospaced))
                                .foregroundStyle(.green)
                            
                            Text("PUBLIC KEY:")
                                .font(.system(.headline, design: .monospaced))
                                .foregroundStyle(.green)
                            
                            Text(recipientKey.publicKey.urlSafeBase64EncodedString())
                                .font(.system(.footnote, design: .monospaced))
                                .foregroundStyle(.green)
                        }
                        .padding()
                        .preferredColorScheme(.dark)
                        .presentationCompactAdaptation(.popover)
                    }
                    
                }
                
                if disclosures.isEmpty {
                    Spacer()
                    
                    Text("No disclosures found.")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.gray)
                    
                    Spacer()
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(disclosures.indices, id: \.self) { index in
                                let disclosure = disclosures[index]
                                
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack(alignment: .top) {
                                        Text(disclosure.author.isEmpty ? "anonymous" : disclosure.author)
                                            .font(.system(.footnote, design: .monospaced))
                                            .foregroundStyle(.green.opacity(0.8))
                                        
                                        Text("\(disclosure.organization!) ✔")
                                            .font(.system(.footnote, design: .monospaced))
                                            .foregroundStyle(.green.opacity(0.4))
                                    }

                                    Text(disclosure.text)
                                        .font(.system(.body, design: .monospaced))
                                        .foregroundStyle(.green)
                                        .padding(6)
                                        .background(Color.black.opacity(0.2))
                                        .cornerRadius(4)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }

                Button(refreshing ? "REFRESHING..." : "[ REFRESH ]") {
                    checkForDisclosures()
                }
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.green)
                .disabled(refreshing)
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
        .padding()
        .onAppear {
            focusState = .name
        }
    }

    func registerRecipient() {
        do {
            try RendezvousPoint.all.registerRecipient(recipient: recipient) { success in
                DispatchQueue.main.async {
                    guard success else {
                        errorState = .visible("Failed to register recipient.")
                        return
                    }
                    state = .inbox
                }
            }
        } catch {
            errorState = .visible("Failed to register recipient.")
        }
    }

    func checkForDisclosures() {
        refreshing = true
        do {
            try RendezvousPoint.all.checkInbox(for: recipient, using: recipientKey) { disclosures in
                DispatchQueue.main.async {
                    self.disclosures.append(contentsOf: disclosures)
                    refreshing = false
                }
            }
        } catch {
            errorState = .visible("Failed to fetch disclosures.")
        }
    }
}
