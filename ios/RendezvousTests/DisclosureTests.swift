//
//  DisclosureTests.swift
//  Rendezvous
//
//  Created by Nora Trapp on 5/16/25.
//

import XCTest
import CryptoKit
@testable import Rendezvous // or your module name

final class DisclosureTests: XCTestCase {
    
    func testEncryptionAndDecryptionRoundTrip() throws {
        let message = "The password is swordfish"
        let disclosure = Disclosure(text: message, author: "nora")

        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = Recipient(name: "test", publicKey: recipientKey.publicKey)

        let encrypted = try disclosure.encrypt(recipient: recipient)
        let decrypted = try encrypted.decrypt(using: recipientKey)

        XCTAssertEqual(decrypted.text, message)
    }

    func testEncryptedCodableRoundTrip() throws {
        let disclosure = Disclosure(text: "Hello!", author: "nora")
        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = Recipient(name: "test", publicKey: recipientKey.publicKey)

        let encrypted = try disclosure.encrypt(recipient: recipient)

        let encoded = try JSONEncoder().encode(encrypted)
        let decoded = try JSONDecoder().decode(Disclosure.Encrypted.self, from: encoded)

        let decrypted = try decoded.decrypt(using: recipientKey)
        XCTAssertEqual(decrypted.text, "Hello!")
    }

    func testShareSplitAndReconstruction() throws {
        let message = "Top secret"
        let disclosure = Disclosure(text: message, author: "nora")

        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = Recipient(name: "test", publicKey: recipientKey.publicKey)

        let encrypted = try disclosure.encrypt(recipient: recipient)

        let shares = try encrypted.makeShares(5, recoveryThreshold: 3)
        XCTAssertEqual(shares.count, 5)

        // Take 3 random shares to reconstruct
        let selectedShares = Array(shares.shuffled().prefix(3))
        let reconstructed = try Disclosure.Encrypted.reconstruct(from: selectedShares)

        let decrypted = try reconstructed.decrypt(using: recipientKey)
        XCTAssertEqual(decrypted.text, message)
    }

    func testShareReconstructionFailsWithTooFewShares() throws {
        let message = "Too few"
        let disclosure = Disclosure(text: message, author: "nora")

        let recipientKey = Curve25519.KeyAgreement.PrivateKey()
        let recipient = Recipient(name: "test", publicKey: recipientKey.publicKey)

        let encrypted = try disclosure.encrypt(recipient: recipient)
        let shares = try encrypted.makeShares(5, recoveryThreshold: 4)

        // Only use 2 shares (below threshold)
        let fewShares = Array(shares.prefix(2))

        XCTAssertThrowsError(try Disclosure.Encrypted.reconstruct(from: fewShares))
    }
}
