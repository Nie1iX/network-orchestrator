import Foundation
import Observation
import SwiftUI

enum TranslatedMessage: Decodable, Sendable {
  case text(String)
  case forms([String: String])
  init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer()
    if let text = try? value.decode(String.self) {
      self = .text(text)
    } else {
      self = .forms(try value.decode([String: String].self))
    }
  }
}
struct PluralCondition: Decodable, Sendable {
  let all: [PluralCondition]?
  let any: [PluralCondition]?
  let integer: Bool?
  let mod: Double?
  let range: [Double]?
  let notRange: [Double]?
  func matches(_ count: Double) -> Bool {
    if let all, !all.allSatisfy({ $0.matches(count) }) { return false }
    if let any, !any.contains(where: { $0.matches(count) }) { return false }
    if let integer, (count.rounded(.down) == count) != integer { return false }
    let value = mod.map { count.truncatingRemainder(dividingBy: $0) } ?? count
    if let range, !(value >= range[0] && value <= range[1]) { return false }
    if let notRange, value >= notRange[0] && value <= notRange[1] { return false }
    return true
  }
}
struct PluralRule: Decodable, Sendable {
  let category: String
  let when: PluralCondition
}
struct TranslationCatalog: Decodable, Sendable {
  let name: String
  let direction: String
  let pluralRules: [PluralRule]
  let messages: [String: TranslatedMessage]
}

@Observable @MainActor final class LocalizationStore {
  static let storageKey = "netmanager.language"
  static let packaged: [String: TranslationCatalog] = {
    guard let url = NativeIcon.bundle.url(forResource: "Localizations", withExtension: "json"),
      let data = try? Data(contentsOf: url),
      let catalogs = try? JSONDecoder().decode([String: TranslationCatalog].self, from: data)
    else { return [:] }
    return catalogs
  }()
  private let defaults: UserDefaults
  private let systemLanguages: [String]
  let catalogs: [String: TranslationCatalog]
  private static let interpolation = try! NSRegularExpression(
    pattern: #"\{([A-Za-z][A-Za-z0-9_]*)\}"#)
  var preference: String {
    didSet {
      guard preference == "system" || catalogs[preference] != nil else {
        preference = oldValue
        return
      }
      defaults.set(preference, forKey: Self.storageKey)
    }
  }
  init(
    defaults: UserDefaults = .standard,
    catalogs: [String: TranslationCatalog] = LocalizationStore.packaged,
    systemLanguages: [String] = Locale.preferredLanguages
  ) {
    self.defaults = defaults
    self.catalogs = catalogs
    self.systemLanguages = systemLanguages
    let saved = defaults.string(forKey: Self.storageKey) ?? "system"
    preference = saved == "system" || catalogs[saved] != nil ? saved : "system"
  }
  var language: String {
    let supported = catalogs.keys.sorted()
    for candidate in preference == "system" ? systemLanguages : [preference] {
      let tag = candidate.replacingOccurrences(of: "_", with: "-").lowercased()
      if let exact = supported.first(where: { $0.lowercased() == tag }) { return exact }
      let base = tag.split(separator: "-").first ?? ""
      if let match = supported.first(where: { $0.lowercased() == base })
        ?? supported.first(where: { $0.lowercased().split(separator: "-").first == base })
      {
        return match
      }
    }
    return "en"
  }
  var direction: LayoutDirection {
    catalogs[language]?.direction == "rtl" ? .rightToLeft : .leftToRight
  }
  var options: [(value: String, title: String)] {
    [("system", "System")] + catalogs.keys.sorted().map { ($0, catalogs[$0]!.name) }
  }
  func text(_ key: String, _ arguments: [String: String] = [:]) -> String {
    // Core errors may carry a technical detail: "Known message (detail)".
    if catalogs["en"]?.messages[key] == nil, key.hasSuffix(")"),
      let range = key.range(of: " ("),
      catalogs["en"]?.messages[String(key[..<range.lowerBound])] != nil
    {
      return text(String(key[..<range.lowerBound]), arguments) + String(key[range.lowerBound...])
    }
    let translated = catalogs[language]?.messages[key]
    let catalog = translated == nil ? catalogs["en"] : catalogs[language]
    let message = translated ?? catalogs["en"]?.messages[key] ?? .text(key)
    let count = abs(Double(arguments["count"] ?? "") ?? .nan)
    let category =
      count.isFinite
      ? catalog?.pluralRules.first(where: { $0.when.matches(count) })?.category ?? "other" : "other"
    let template: String
    switch message {
    case .text(let text): template = text
    case .forms(let forms): template = forms[category] ?? forms["other"] ?? key
    }
    if arguments.isEmpty { return template }
    let matches = Self.interpolation.matches(
      in: template, range: NSRange(template.startIndex..., in: template))
    var result = template
    for match in matches.reversed() {
      guard let nameRange = Range(match.range(at: 1), in: template),
        let value = arguments[String(template[nameRange])],
        let replacementRange = Range(match.range, in: result)
      else { continue }
      result.replaceSubrange(replacementRange, with: value)
    }
    return result
  }
}
@MainActor enum L10n {
  static var shared = LocalizationStore()
  static func text(_ key: String, _ arguments: [String: String] = [:]) -> String {
    shared.text(key, arguments)
  }
}
