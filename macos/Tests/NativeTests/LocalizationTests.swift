import Foundation
import Testing

@testable import NetworkOrchestrator

@Test @MainActor func packagedTranslationsDecodeBothLanguages() throws {
  let url = try #require(NativeIcon.bundle.url(forResource: "Localizations", withExtension: "json"))
  let catalogs = try JSONDecoder().decode(
    [String: TranslationCatalog].self, from: Data(contentsOf: url))
  #expect(catalogs["en"]?.messages.count ?? 0 > 0)
  #expect(catalogs["ru"]?.messages["Home"] != nil)
}

@Test @MainActor func languageSelectionPersistsAndUsesPackagedCatalogs() throws {
  let name = "netorch-localization-test-" + UUID().uuidString
  let defaults = try #require(UserDefaults(suiteName: name))
  defer { defaults.removePersistentDomain(forName: name) }
  let store = LocalizationStore(defaults: defaults, systemLanguages: ["ru-RU"])
  #expect(store.language == "ru")
  #expect(store.text("Home") == "Главная")
  store.preference = "en"
  #expect(store.text("Home") == "Home")
  #expect(LocalizationStore(defaults: defaults, systemLanguages: ["ru-RU"]).language == "en")
  store.preference = "invalid"
  #expect(store.preference == "en")
}

@Test @MainActor func nativePluralRulesAndLiteralArgumentsMatchTheWebContract() throws {
  let name = "netorch-localization-test-" + UUID().uuidString
  let defaults = try #require(UserDefaults(suiteName: name))
  defer { defaults.removePersistentDomain(forName: name) }
  let store = LocalizationStore(defaults: defaults, systemLanguages: ["ru"])
  for (count, suffix) in [
    (0, "маршрутов"), (1, "маршрут"), (2, "маршрута"), (5, "маршрутов"), (11, "маршрутов"),
    (21, "маршрут"), (22, "маршрута"),
  ] {
    #expect(store.text("{count} routes", ["count": String(count)]) == "\(count) \(suffix)")
  }
  #expect(
    store.text("No connections match “{query}”.", ["query": "<b>{count}</b>", "count": "8"])
      == "Нет подключений по запросу «<b>{count}</b>».")
  #expect(store.text("Untranslated technical message") == "Untranslated technical message")
}
