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
    
    let issuer: URL
    fileprivate let raw: String
    private(set) lazy var decoded: Decoded? = {
        let jwtSegments = raw.split(separator: ".")
        guard jwtSegments.count == 3 else { return nil }
        var jwtPayload = String(jwtSegments[1])
        jwtPayload = jwtPayload.padding(toLength: jwtPayload.count + (jwtPayload.count % 4), withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: jwtPayload) else { return nil }
        var decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(Decoded.self, from: data)
    }()
    
    init(issuer: URL, raw: String) {
        self.issuer = issuer
        self.raw = raw
    }
}

extension URLRequest {
    mutating func setRendezvousCredential(_ credential: Credential) {
        setValue("Bearer \(credential.raw)", forHTTPHeaderField: "Authorization")
    }
}
