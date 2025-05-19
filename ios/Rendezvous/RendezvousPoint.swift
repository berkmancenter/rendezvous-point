//
//  RendezvousPoint.swift
//  Rendezvous
//
//  Created by Nora Trapp on 5/16/25.
//

import Foundation
import CryptoKit

struct RendezvousPoint {
    let url: URL
    
    static var all = [
        RendezvousPoint(url: URL(string: "https://rp1-246724171794.us-central1.run.app")!),
        RendezvousPoint(url: URL(string: "https://rp2-246724171794.us-central1.run.app")!),
        RendezvousPoint(url: URL(string: "https://rp3-246724171794.us-central1.run.app")!),
    ]
    
    private struct CredentialResponse: Decodable {
        let credential: String
        let organization: String
    }
    
    func requestCredential(completionHandler: @escaping (Credential?) -> Void) {
        DomainFronting.googleFrontedDataTask(
            with: URLRequest(url: url.appendingPathComponent("credential"))
        ) { data, response, error in
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                return completionHandler(nil)
            }
            
            guard let data = data, let credentialResponse = try? JSONDecoder().decode(CredentialResponse.self, from: data) else {
                return completionHandler(nil)
            }
            
            completionHandler(.init(
                issuer: self,
                raw: credentialResponse.credential
            ))
        }.resume()
    }
    
    func registerRecipient(_ recipient: Recipient, completion: @escaping (Bool) -> Void) throws {
        var request = URLRequest(url: url.appendingPathComponent("register"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(recipient)
        
        DomainFronting.googleFrontedDataTask(with: request) { data, response, error in
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                return completion(false)
            }
            completion(true)
        }.resume()
    }
    
    private struct ChallengeResponse: Codable {
        let token: Data
        let nonce: Data
        let publicKey: Data
    }

    private struct ChallengeAuth: Codable {
        let encryptedToken: Data
        let nonce: Data
    }
    
    private func fetchInboxChallenge(
        for recipient: Recipient,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        completion: @escaping (String?) -> Void
    ) throws {
        let challengeReq = URLRequest(url: url.appendingPathComponent("inbox/\(recipient.publicKey.urlSafeBase64EncodedString())/challenge"))
        
        DomainFronting.googleFrontedDataTask(with: challengeReq) { data, response, error in
            guard let data = data,
                  let challengeResponse = try? JSONDecoder().decode(ChallengeResponse.self, from: data),
                  let response = response as? HTTPURLResponse, response.statusCode == 200
            else {
                completion(nil)
                return
            }
            
            do {
                let serverPubKey = try Curve25519.KeyAgreement.PublicKey(
                    rawRepresentation: challengeResponse.publicKey
                )
                let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: serverPubKey)
                let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                    using: SHA256.self,
                    salt: Data(),
                    sharedInfo: Data(),
                    outputByteCount: 32
                )
                
                let auth = ChallengeAuth(
                    encryptedToken: try AES.GCM.seal(challengeResponse.token, using: symmetricKey).combined!,
                    nonce: challengeResponse.nonce
                )

                let encodedAuth = try JSONEncoder().encode(auth)
                let authString = "Bearer \(encodedAuth.base64EncodedString())"

                completion(authString)
            } catch {
                completion(nil)
            }
        }.resume()
    }
    
    private struct InboxResponse: Codable {
        let id: UUID
        let org: String
        let share: Data
    }
    
    func checkInbox(
        for recipient: Recipient,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        completion: @escaping ([String: [UUID: Disclosure.Share]]?) -> Void
    ) throws {
        try fetchInboxChallenge(for: recipient, using: privateKey) { authToken in
            guard let authToken = authToken else {
                return completion(nil)
            }
            
            var inboxReq = URLRequest(url: url.appendingPathComponent("inbox/\(recipient.publicKey.urlSafeBase64EncodedString())"))
            inboxReq.setValue(authToken, forHTTPHeaderField: "Authorization")
            
            DomainFronting.googleFrontedDataTask(with: inboxReq) { data, response, error in
                guard let data = data,
                      let items = try? JSONDecoder().decode([InboxResponse].self, from: data),
                      let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                    completion(nil)
                    return
                }
                
                completion(Dictionary(grouping: items, by: { $0.org }).mapValues { values in
                    Dictionary(uniqueKeysWithValues: values.map { ($0.id, Disclosure.Share(data: $0.share)) })
                })
            }.resume()
        }
    }
    
    func deleteInboxShare(
        disclosureId: UUID,
        for recipient: Recipient,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        completion: @escaping (Bool) -> Void
    ) throws {
        try fetchInboxChallenge(for: recipient, using: privateKey) { authToken in
            guard let authToken = authToken else {
                return completion(false)
            }
            
            var inboxDeleteReq = URLRequest(url: url.appendingPathComponent("inbox/\(recipient.publicKey.urlSafeBase64EncodedString())/\(disclosureId.uuidString)"))
            inboxDeleteReq.httpMethod = "DELETE"
            inboxDeleteReq.setValue(authToken, forHTTPHeaderField: "Authorization")
            
            DomainFronting.googleFrontedDataTask(with: inboxDeleteReq) { data, response, error in
                guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                    return completion(false)
                }
                completion(true)
            }.resume()
        }
    }
    
    func requestRecipients(
        completionHandler: @escaping ([Recipient]) -> Void
    ) {
        let request = URLRequest(url: url.appendingPathComponent("recipients"))
        
        DomainFronting.googleFrontedDataTask(with: request) { data, response, error in
            guard let response = response as? HTTPURLResponse, response.statusCode == 200,
                  let data = data,
                  let recipients = try? JSONDecoder().decode([Recipient].self, from: data) else {
                completionHandler([])
                return
            }
            
            completionHandler(recipients)
        }.resume()
    }
    
    private struct DiscloseRequest: Encodable {
        let id: UUID
        let recipient: Data
        let share: Data
    }
    
    func submitDisclosure(
        credential: Credential,
        recipient: Recipient,
        disclosureId: UUID,
        share: Disclosure.Share,
        completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void
    ) throws {
        let disclosureRequest = DiscloseRequest(
            id: disclosureId,
            recipient: recipient.publicKey.rawRepresentation,
            share: share.data
        )
        let body = try JSONEncoder().encode(disclosureRequest)
        
        var request = URLRequest(url: url.appending(path: "disclose"))
        request.setRendezvousCredential(credential)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        
        DomainFronting.googleFrontedDataTask(with: request, completionHandler: completionHandler).resume()
    }
}

extension Array where Element == RendezvousPoint {
    func requestCredentials(
        completionHandler: @escaping ([Credential]) -> Void
    ) {
        let group = DispatchGroup()
        let syncQueue = DispatchQueue(label: "credentials.sync")
        var credentials: [Credential] = []
        
        for point in self {
            group.enter()
            point.requestCredential { credential in
                if let credential = credential {
                    syncQueue.async {
                        credentials.append(credential)
                    }
                }
                group.leave()
            }
        }
        
        group.notify(queue: .main) {
            completionHandler(credentials)
        }
    }
    
    func registerRecipient(
        recipient: Recipient,
        completionHandler: @escaping (Bool) -> Void
    ) throws {
        let group = DispatchGroup()
        let syncQueue = DispatchQueue(label: "register.sync")
        var overallSuccess = true
        
        for rp in self {
            group.enter()
            try rp.registerRecipient(recipient) { success in
                if !success {
                    syncQueue.async {
                        overallSuccess = false
                    }
                }
                group.leave()
            }
        }
        
        group.notify(queue: .main) {
            completionHandler(overallSuccess)
        }
    }
    
    func requestCommonRecipients(
        completionHandler: @escaping ([Recipient]) -> Void
    ) {
        let group = DispatchGroup()
        let syncQueue = DispatchQueue(label: "recipients.sync")
        var allRecipientSets: [[Recipient]] = []
        
        for point in self {
            group.enter()
            point.requestRecipients { recipients in
                syncQueue.async {
                    allRecipientSets.append(recipients)
                }
                group.leave()
            }
        }
        
        group.notify(queue: .main) {
            guard let firstSet = allRecipientSets.first else {
                completionHandler([])
                return
            }
            
            // Intersect based on raw public key data
            let common = firstSet.filter { candidate in
                allRecipientSets.dropFirst().allSatisfy { set in
                    set.contains(where: { $0.publicKey.rawRepresentation == candidate.publicKey.rawRepresentation })
                }
            }
            
            completionHandler(common)
        }
    }
    
    func checkInbox(
        for recipient: Recipient,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        completion: @escaping ([Disclosure]) -> Void
    ) throws {
        let group = DispatchGroup()
        let syncQueue = DispatchQueue(label: "inbox.sync")
        var allShares: [String: [UUID: [Disclosure.Share]]] = [:]
        
        for rp in self {
            group.enter()
            try rp.checkInbox(for: recipient, using: privateKey) { shares in
                syncQueue.async(execute: DispatchWorkItem(block: {
                    shares?.forEach { org, orgShares in
                        orgShares.forEach { id, share in
                            allShares[org, default: [:]][id, default: []].append(share)
                        }
                    }
                }))
                group.leave()
            }
        }
        
        group.notify(queue: .main) {
            var disclosures: [Disclosure] = []
            for (org, orgShares) in allShares {
                for (id, shares) in orgShares {
                    guard shares.count >= self.count else { continue }
                    do {
                        let encrypted = try Disclosure.Encrypted.reconstruct(from: shares)
                        var disclosure = try encrypted.decrypt(using: privateKey)
                        disclosure.organization = org
                        disclosures.append(disclosure)
                        
                        try deleteDisclosure(disclosureId: id, for: recipient, using: privateKey) { success in
                            // TODO: error if deletion fails
                        }
                    } catch {
                        continue
                    }
                }
            }
            completion(disclosures)
        }
    }
    
    func deleteDisclosure(
        disclosureId: UUID,
        for recipient: Recipient,
        using privateKey: Curve25519.KeyAgreement.PrivateKey,
        completion: @escaping (Bool) -> Void
    ) throws {
        let group = DispatchGroup()
        let syncQueue = DispatchQueue(label: "inbox.delete")
        var overallSuccess = true
        
        for rp in self {
            group.enter()
            try rp.deleteInboxShare(disclosureId: disclosureId, for: recipient, using: privateKey) { success in
                if !success {
                    syncQueue.async {
                        overallSuccess = false
                    }
                }
                group.leave()
            }
        }
        
        group.notify(queue: .main) {
            completion(overallSuccess)
        }
    }
}

extension Curve25519.KeyAgreement.PublicKey {
    func urlSafeBase64EncodedString() -> String {
        rawRepresentation
            .base64EncodedString()
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
    }
}
