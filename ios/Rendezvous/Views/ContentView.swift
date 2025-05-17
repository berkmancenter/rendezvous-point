//
//  ContentView.swift
//  Rendezvous
//
//  Created by Nora Trapp on 5/16/25.
//

import SwiftUI
import CryptoKit

struct ContentView: View {
    enum ContentState {
        case splash
        case receive
        case transmit([Credential])
    }
    
    enum ErrorSheetState: Equatable {
        case hidden
        case visible(String)
    }
    
    @State private var contentState: ContentState = .splash
    @State private var errorState: ErrorSheetState = .hidden

    var body: some View {
        let isErrorSheetVisible = Binding<Bool>(get: { errorState != .hidden }, set: { _ in })
        
        return ZStack {
            LinearGradient(
                gradient: Gradient(colors: [Color.black, Color(red: 0.05, green: 0.05, blue: 0.05)]),
                startPoint: .top,
                endPoint: .bottom
            ).ignoresSafeArea()
            
            switch contentState {
            case .splash:
                ZStack(alignment: .bottom) {
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
                        
                        Button("[ VERIFY ]") { requestCredentials() }
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.bold)
                            .foregroundStyle(.green)
                        
                        Spacer()
                    }
                    
                    Button("[ RECEIVE ]") {
                        contentState = .receive
                    }
                    .font(.system(.footnote, design: .monospaced))
                    .fontWeight(.bold)
                    .foregroundStyle(.green.opacity(0.6))
                    .padding()
                }
            case .transmit(let credentials):
                TransmitView(credentials: credentials, onAbort: { contentState = .splash })
            case .receive:
                ReceiveView(onAbort: { contentState = .splash })
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
    }
    
    func requestCredentials() {
        RendezvousPoint.all.requestCredentials { credentials in
            DispatchQueue.main.async {
                guard credentials.commonOrganization != nil else {
                    errorState = .visible("Verification failed, please try again")
                    return
                }
                
                contentState = .transmit(credentials)
            }
        }
    }
}

#Preview {
    ContentView()
}
