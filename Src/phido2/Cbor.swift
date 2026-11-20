import CFido2
import Foundation

/// A key of a CBOR map. CTAP2 uses only integers and text strings as keys.
enum CBORKey: Hashable {
    case int(Int64)
    case text(String)
}

/// A decoded CBOR data item, limited to what CTAP2 messages contain.
///
/// Decoding is done by libcbor, the library libfido2 itself uses; this type only gives the
/// result a shape that Swift code can pattern-match on.
indirect enum CBORValue: Equatable {
    /// An unsigned or negative integer.
    case int(Int64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    case map([CBORKey: CBORValue])
    case bool(Bool)
    case null
    /// A valid item this tool has no use for: a float, a tag, `undefined`.
    case other

    /// Decodes the first CBOR item in `data`.
    ///
    /// - Parameter data: The encoded bytes; anything after the first item is left alone.
    /// - Returns: The item and the number of bytes it occupied, or `nil` if `data` does not
    ///   start with well-formed CBOR, or uses integers beyond 64 bits signed, indefinite-length
    ///   strings or map keys other than integers and text, none of which CTAP2 allows.
    static func decode(_ data: Data) -> (value: CBORValue, consumed: Int)? {
        guard !data.isEmpty else { return nil }
        var result = cbor_load_result()
        var item = data.withUnsafeBytes { cbor_load($0.bindMemory(to: UInt8.self).baseAddress, data.count, &result) }
        guard let loaded = item else { return nil }
        defer { cbor_decref(&item) }
        guard result.error.code == CBOR_ERR_NONE, let value = convert(loaded) else { return nil }
        return (value, result.read)
    }

    private static func convert(_ item: UnsafeMutablePointer<cbor_item_t>) -> CBORValue? {
        switch cbor_typeof(item) {
        case CBOR_TYPE_UINT:
            guard let value = Int64(exactly: cbor_get_int(item)) else { return nil }
            return .int(value)
        case CBOR_TYPE_NEGINT:
            // The encoded number n stands for -1 - n.
            guard let value = Int64(exactly: cbor_get_int(item)) else { return nil }
            return .int(-1 - value)
        case CBOR_TYPE_BYTESTRING:
            guard cbor_bytestring_is_definite(item) else { return nil }
            let length = cbor_bytestring_length(item)
            guard length > 0, let handle = cbor_bytestring_handle(item) else { return .bytes(Data()) }
            return .bytes(Data(bytes: handle, count: length))
        case CBOR_TYPE_STRING:
            guard cbor_string_is_definite(item) else { return nil }
            let length = cbor_string_length(item)
            guard length > 0, let handle = cbor_string_handle(item) else { return .text("") }
            return .text(String(decoding: UnsafeBufferPointer(start: handle, count: length), as: UTF8.self))
        case CBOR_TYPE_ARRAY:
            let count = cbor_array_size(item)
            guard count > 0, let handle = cbor_array_handle(item) else { return .array([]) }
            var elements: [CBORValue] = []
            for i in 0..<count {
                guard let element = handle[i], let value = convert(element) else { return nil }
                elements.append(value)
            }
            return .array(elements)
        case CBOR_TYPE_MAP:
            let count = cbor_map_size(item)
            guard count > 0, let handle = cbor_map_handle(item) else { return .map([:]) }
            var entries: [CBORKey: CBORValue] = [:]
            for i in 0..<count {
                guard let keyItem = handle[i].key, let valueItem = handle[i].value,
                      let key = convert(keyItem), let value = convert(valueItem) else { return nil }
                switch key {
                case .int(let number): entries[.int(number)] = value
                case .text(let text): entries[.text(text)] = value
                default: return nil
                }
            }
            return .map(entries)
        case CBOR_TYPE_FLOAT_CTRL:
            guard cbor_float_ctrl_is_ctrl(item) else { return .other }
            if cbor_is_bool(item) { return .bool(cbor_get_bool(item)) }
            return cbor_is_null(item) ? .null : .other
        default:
            return .other
        }
    }

    // MARK: Typed access

    var intValue: Int64? { if case .int(let value) = self { value } else { nil } }
    var bytesValue: Data? { if case .bytes(let value) = self { value } else { nil } }
    var textValue: String? { if case .text(let value) = self { value } else { nil } }
    var boolValue: Bool? { if case .bool(let value) = self { value } else { nil } }
    var arrayValue: [CBORValue]? { if case .array(let value) = self { value } else { nil } }
    var mapValue: [CBORKey: CBORValue]? { if case .map(let value) = self { value } else { nil } }

    /// The value under an integer key, if this is a map that has it.
    subscript(key: Int64) -> CBORValue? { mapValue?[.int(key)] }
    /// The value under a text key, if this is a map that has it.
    subscript(key: String) -> CBORValue? { mapValue?[.text(key)] }
}
