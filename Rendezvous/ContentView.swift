//
//  ContentView.swift
//  Rendezvous
//
//  Created by Nora Trapp on 3/26/25.
//

import SwiftUI

struct ContentView: View {
    enum FocusedField {
        case disclosure
    }
    
    enum ContentState {
        case splash
        case confirmation(Credential)
        case disclosure(Credential)
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
    
    @State private var contentState: ContentState = .splash {
        didSet {
            disclosureState = .awaiting
            disclosureText = Self.disclosurePrompt
        }
    }
    @State private var disclosureState: DisclosureState = .awaiting
    @State private var errorState: ErrorSheetState = .hidden
    @FocusState private var focusState: FocusedField?

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
            LinearGradient(
                gradient: Gradient(colors: [Color.black, Color(red: 0.05, green: 0.05, blue: 0.05)]),
                startPoint: .top,
                endPoint: .bottom
            ).ignoresSafeArea()
            
            switch contentState {
            case .splash:
                VStack(spacing: 40) {
                    Spacer()
                    Text("""

    
           :::::::::  :::::::::: ::::    ::: :::::::::  :::::::::: ::::::::: :::     :::  ::::::::  :::    :::  ::::::::
           :+:    :+: :+:        :+:+:   :+: :+:    :+: :+:             :+:  :+:     :+: :+:    :+: :+:    :+: :+:    :+:
    +:+    +:+ +:+        :+:+:+  +:+ +:+    +:+ +:+            +:+   +:+     +:+ +:+    +:+ +:+    +:+ +:+        
         +#++:++#:  +#++:++#   +#+ +:+ +#+ +#+    +:+ +#++:++#      +#+    +#+     +:+ +#+    +:+ +#+    +:+ +#++:++#++  
        +#+    +#+ +#+        +#+  +#+#+# +#+    +#+ +#+          +#+      +#+   +#+  +#+    +#+ +#+    +#+        +#+   
       #+#    #+# #+#        #+#   #+#+# #+#    #+# #+#         #+#        #+#+#+#   #+#    #+# #+#    #+# #+#    #+#    
      ###    ### ########## ###    #### #########  ########## #########     ###      ########   ########   ########      
    """)
                        .font(.system(size: 5, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundStyle(.green)
                        .multilineTextAlignment(.center)

                    Button("[ VERIFY ]") { requestCredential() }
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundStyle(.green)
                    
                    Spacer()
                }
            case .confirmation(var credential):
                VStack(spacing: 20) {
                    Spacer()
                    
                    Text("We found \"\(credential.decoded!.org)\" as your organization.")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.green)
                        .padding()

                    Button("[ CONTINUE ]") {
                        contentState = .disclosure(credential)
                        timeRemaining = credential.decoded!.exp.timeIntervalSinceNow
                    }
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundStyle(.green)

                    Button("[ ABORT ]") { contentState = .splash }
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundStyle(.red)

                    Spacer()
                }
                .padding()
            case .disclosure(var credential):
                ScrollView {
                    VStack(spacing: 20) {
                        VStack(spacing: 10) {
                            Text("ORG: \(credential.decoded!.org)")
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

                            Button("[ ERASE ]") {
                                contentState = .splash
                            }
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.bold)
                            .foregroundStyle(.red)
                        }

                        Divider().background(Color.green)

                        VStack(alignment: .leading, spacing: 10) {
                            Text("BEGIN DISCLOSURE")
                                .font(.system(.title2, design: .monospaced))
                                .foregroundStyle(.green)

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
                                submitDisclosure(credential: credential)
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
                                .disabled(
                                    disclosureText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                    || disclosureState == .submitting
                                )

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
        }
    }
    
    private struct CredentialResponse: Decodable {
        let credential: String
        let organization: String
    }
    
    func requestCredential() {
        // TODO: request credential from multiple RPs
        DomainFronting.googleFrontedDataTask(
            with: URLRequest(url: URL(string: "https://rendezvous-1065111780930.us-central1.run.app/credential")!)
        ) { data, response, error in
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                errorState = .visible("Verification failed, please try again")
                return
            }
            
            guard let data = data, let credentialResponse = try? JSONDecoder().decode(CredentialResponse.self, from: data) else {
                errorState = .visible("Verification failed, please try again")
                return
            }
            
            // TODO: persist credentials
            contentState = .confirmation(.init(
                issuer: URL(string: "https://rendezvous-1065111780930.us-central1.run.app")!,
                raw: credentialResponse.credential
            ))
        }.resume()
    }
    
    private struct DiscloseRequest: Encodable {
        let id: UUID
        let share: Data
    }

    func submitDisclosure(credential: Credential) {
        disclosureState = .submitting
        // TODO: secret sharing, encryption, recipient, etc.
        let disclosureRequest = DiscloseRequest(
            id: .init(),
            share: Data()
        )
        guard let body = try? JSONEncoder().encode(disclosureRequest) else {
            disclosureState = .awaiting
            errorState = .visible("Failed to submit disclosure, please try again")
            return
        }
        
        var request = URLRequest(url: URL(string: "https://rendezvous-1065111780930.us-central1.run.app/disclose")!)
        request.setRendezvousCredential(credential)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        
        DomainFronting.googleFrontedDataTask(with: request) { _, response, _ in
            DispatchQueue.main.async {
                guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                    disclosureState = .awaiting
                    errorState = .visible("Failed to submit disclosure, please try again")
                    return
                }
                
                disclosureState = .submitted
                disclosureText = Self.disclosurePrompt
            }
        }.resume()
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

#Preview {
    ContentView()
}
