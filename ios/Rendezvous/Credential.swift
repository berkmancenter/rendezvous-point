//
//  Credential.swift
//  Rendezvous
//
//  Created by Nora Trapp on 3/26/25.
//

import Foundation

struct Credential {
    struct Decoded: Codable {
        let org: String
        let iat: Date
        let exp: Date
    }
    
    let issuer: RendezvousPoint
    fileprivate let raw: String
    var decoded: Decoded? {
        let jwtSegments = raw.split(separator: ".")
        guard jwtSegments.count == 3 else { return nil }
        var jwtPayload = String(jwtSegments[1])
        jwtPayload = jwtPayload.padding(toLength: jwtPayload.count + (jwtPayload.count % 4), withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: jwtPayload) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(Decoded.self, from: data)
    }
    
    init(issuer: RendezvousPoint, raw: String) {
        self.issuer = issuer
        self.raw = raw
    }
}

extension URLRequest {
    mutating func setRendezvousCredential(_ credential: Credential) {
        setValue("Bearer \(credential.raw)", forHTTPHeaderField: "Authorization")
    }
}

extension Array where Element == Credential {
    /// Returns the common organization shared across the collection of credentials, or nil if they mismatch.
    var commonOrganization: String? {
        let orgs = Set(compactMap { $0.decoded?.org })
        return orgs.count == 1 ? orgs.first : nil
    }
    
    /// Returns the lowest expiry time for the collection of credentials
    var soonestExpiration: Date? {
        self.compactMap { $0.decoded?.exp }.min()
    }
    
    /// Submit a disclosure by sending an encrypted share to each credential's issuer
    func submitDisclosure(
        _ disclosure: Disclosure,
        recipient: Recipient,
        completionHandler: @escaping (Bool) -> Void
    ) throws {
        let group = DispatchGroup()
        let syncQueue = DispatchQueue(label: "disclose.sync")
        var success = true

        let encrypted = try disclosure.encrypt(recipient: recipient)
        // TODO: support M-of-N threshold sharing
        let shares = try encrypted.makeShares(count, recoveryThreshold: count)
        let disclosureId = UUID()
        
        for (credential, share) in zip(self, shares) {
            group.enter()
            do {
                try credential.issuer.submitDisclosure(
                    credential: credential,
                    recipient: recipient,
                    disclosureId: disclosureId,
                    share: share
                ) { _, response, error in
                    if let http = response as? HTTPURLResponse, http.statusCode != 200 || error != nil {
                        syncQueue.async { success = false }
                    }
                    group.leave()
                }
            } catch {
                syncQueue.async { success = false }
                group.leave()
            }
        }
        
        group.notify(queue: .main) {
            completionHandler(success)
        }
    }
}
