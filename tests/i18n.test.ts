import assert from "node:assert/strict";
import test from "node:test";
import { resolveLanguage, translateMessage, type Catalogs } from "../src/i18n/engine.ts";

const catalogs: Catalogs = {
  en: { name: "English", direction: "ltr", pluralRules: [{ category: "one", when: { range: [1, 1] } }], messages: {
    Home: "Home", "Hello {name}": "Hello {name}", missing: "English fallback",
    routes: { one: "{count} route", other: "{count} routes" },
  } },
  ru: { name: "Русский", direction: "ltr", pluralRules: [
    { category: "one", when: { all: [{ integer: true }, { mod: 10, range: [1, 1] }, { mod: 100, notRange: [11, 11] }] } },
    { category: "few", when: { all: [{ integer: true }, { mod: 10, range: [2, 4] }, { mod: 100, notRange: [12, 14] }] } },
    { category: "many", when: { integer: true } },
  ], messages: { Home: "Главная", "Hello {name}": "Привет, {name}", routes: {
    one: "{count} маршрут", few: "{count} маршрута", many: "{count} маршрутов", other: "{count} маршрута",
  } } },
};

test("system language resolves regional tags and falls back to English", () => {
  assert.equal(resolveLanguage("system", ["fr-FR", "ru-RU"], catalogs), "ru");
  assert.equal(resolveLanguage("en", ["ru"], catalogs), "en");
  assert.equal(resolveLanguage("system", ["de-DE"], catalogs), "en");
});

test("missing translations fall back to English and unknown keys remain readable", () => {
  assert.equal(translateMessage(catalogs, "ru", "Home"), "Главная");
  assert.equal(translateMessage(catalogs, "ru", "missing"), "English fallback");
  assert.equal(translateMessage(catalogs, "unknown", "Home"), "Home");
  assert.equal(translateMessage(catalogs, "ru", "New source text"), "New source text");
  assert.equal(translateMessage(catalogs, "ru", "constructor"), "constructor");
  assert.equal(translateMessage(catalogs, "__proto__", "toString"), "toString");
});

test("named arguments stay literal, including HTML and other placeholder names", () => {
  const value = "<script>{count}</script>";
  assert.equal(translateMessage(catalogs, "ru", "Hello {name}", { name: value, count: 7 }), `Привет, ${value}`);
});

test("English and Russian count forms include zero, teens, 21, 22 and fractions", () => {
  for (const [count, suffix] of [[0, "маршрутов"], [1, "маршрут"], [2, "маршрута"], [5, "маршрутов"], [11, "маршрутов"], [21, "маршрут"], [22, "маршрута"], [1.5, "маршрута"]] as const) {
    assert.equal(translateMessage(catalogs, "ru", "routes", { count }), `${count} ${suffix}`);
  }
  assert.equal(translateMessage(catalogs, "en", "routes", { count: 1 }), "1 route");
  assert.equal(translateMessage(catalogs, "en", "routes", { count: 2 }), "2 routes");
});
