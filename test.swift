import Alamofire
import CryptoKit
import Foundation
import Security

enum PinningError: Error {
    case noMatchingPin
    case invalidPin(String)
}

/// Hash algorithm named by the pin prefix, e.g. "sha256/<base64>".
enum PinAlgorithm: String, CaseIterable {
    case sha256, sha384, sha512

    func base64Hash(_ data: Data) -> String {
        switch self {
        case .sha256: return Data(SHA256.hash(data: data)).base64EncodedString()
        case .sha384: return Data(SHA384.hash(data: data)).base64EncodedString()
        case .sha512: return Data(SHA512.hash(data: data)).base64EncodedString()
        }
    }
}

final class SPKIHashTrustEvaluator: ServerTrustEvaluating {
    private let pinsByAlgorithm: [PinAlgorithm: Set<String>]

    /// - Parameter pins: Strings like "sha256/sH2rJDLY9X2RhS+f6aLLKVhgasFA4jtAZvzZbUxZyFo="
    init(pins: [String]) throws {
        var map: [PinAlgorithm: Set<String>] = [:]
        for pin in pins {
            // Split only on the FIRST "/" — Base64 itself can contain "/"
            let parts = pin.split(separator: "/", maxSplits: 1)
            guard parts.count == 2,
                  let algorithm = PinAlgorithm(rawValue: parts[0].lowercased()),
                  Data(base64Encoded: String(parts[1])) != nil else {
                throw PinningError.invalidPin(pin)
            }
            map[algorithm, default: []].insert(String(parts[1]))
        }
        guard !map.isEmpty else { throw PinningError.invalidPin("<empty pin list>") }
        self.pinsByAlgorithm = map
    }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        try trust.af.performDefaultValidation(forHost: host) // chain + hostname

        let spkis = trust.af.publicKeys.compactMap(Self.spkiData)
        let matched = spkis.contains { spki in
            pinsByAlgorithm.contains { algorithm, pins in
                pins.contains(algorithm.base64Hash(spki))
            }
        }

        guard matched else {
            throw AFError.serverTrustEvaluationFailed(
                reason: .customEvaluationFailed(error: PinningError.noMatchingPin))
        }
    }

    // MARK: - SPKI construction

    private static let rsaKeyType = kSecAttrKeyTypeRSA as String
    private static let ecKeyType  = kSecAttrKeyTypeECSECPrimeRandom as String

    /// DER-encoded SubjectPublicKeyInfo (same bytes openssl hashes)
    static func spkiData(_ key: SecKey) -> Data? {
        guard let attrs = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attrs[kSecAttrKeyType] as? String,
              let bits = attrs[kSecAttrKeySizeInBits] as? Int,
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let spki = spkiDER(type: type, bits: bits, raw: [UInt8](raw)) else {
            return nil
        }
        return Data(spki)
    }

    private static func spkiDER(type: String, bits: Int, raw: [UInt8]) -> [UInt8]? {
        let algorithmID: [UInt8]

        switch type {
        case rsaKeyType:
            // AlgorithmIdentifier { rsaEncryption, NULL } — any key size
            algorithmID = [0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]

        case ecKeyType:
            // raw must be an uncompressed point: 0x04 || X || Y
            guard raw.first == 0x04 else { return nil }
            let ecPublicKeyOID: [UInt8] = [0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01]
            let curveOID: [UInt8]
            switch bits {
            case 256: curveOID = [0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07] // P-256
            case 384: curveOID = [0x06,0x05,0x2b,0x81,0x04,0x00,0x22]                // P-384
            case 521: curveOID = [0x06,0x05,0x2b,0x81,0x04,0x00,0x23]                // P-521
            default: return nil
            }
            algorithmID = tlv(0x30, ecPublicKeyOID + curveOID)

        default:
            return nil
        }

        let subjectPublicKey = tlv(0x03, [0x00] + raw) // BIT STRING, 0 unused bits
        return tlv(0x30, algorithmID + subjectPublicKey)
    }

    private static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + derLength(content.count) + content
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        guard length >= 0x80 else { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var value = length
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}
