import SwiftUI

/// Routes that exist only while a condition holds, for example "on the office
/// LAN, reach the internal networks directly". The helper evaluates the
/// condition against the interfaces' addresses on every network change.
struct ConditionsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var editing: RuleDraft?
  @State private var deleting: ConditionalRuleEntry?

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack {
        Text(L10n.text("cond.subtitle")).font(.system(size: 11.9)).foregroundStyle(p.secondary)
        Spacer(minLength: 12)
        Button(L10n.text("cond.newRule")) { editing = RuleDraft() }
          .buttonStyle(TauriButtonStyle(kind: .accent)).disabled(!model.canUseRules)
      }
      if !model.canUseRules {
        AppEmptyState { Text(L10n.text("native.rules.needsHelper")) }
      } else if model.rules.isEmpty {
        AppEmptyState { Text(L10n.text("cond.emptyTitle")) }
      } else {
        VStack(alignment: .leading, spacing: 0) {
          ForEach(model.rules) { entry in row(entry) }
        }
      }
    }
    // The helper keeps evaluating; the page follows while it is open.
    .task {
      while !Task.isCancelled {
        await model.loadRules()
        try? await Task.sleep(for: .seconds(3))
      }
    }
    .sheet(item: Binding(get: { editing.map(RuleDraftBox.init) }, set: { editing = $0?.draft })) { box in
      RuleSheet(model: model, draft: box.draft) { editing = nil }
        .environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
    .alert(
      L10n.text("cond.deleteTitle"),
      isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
      presenting: deleting
    ) { entry in
      Button(L10n.text("common.delete"), role: .destructive) {
        Task { await model.deleteRule(entry) }
      }
      Button(L10n.text("common.cancel"), role: .cancel) {}
    } message: { entry in
      Text(L10n.text("cond.deleteConfirm", ["name": entry.rule.name]))
    }
  }

  private func row(_ entry: ConditionalRuleEntry) -> some View {
    let status = entry.status
    return VStack(alignment: .leading, spacing: 5) {
      HStack(spacing: 8) {
        Text(entry.rule.name).font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        AppBadge(text: status.state.label, color: status.state.badgeColor)
        Text(entry.rule.id).font(.system(size: 10.92, design: .monospaced)).foregroundStyle(p.muted)
        Spacer(minLength: 12)
        if status.state == .active || status.appliedRoutes > 0 {
          Text(
            L10n.text(
              "cond.installedCount",
              [
                "applied": String(status.appliedRoutes),
                "count": String(entry.rule.routes.count),
              ])
          ).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
        Toggle(
          "",
          isOn: Binding(
            get: { entry.rule.enabled },
            set: { value in Task { await model.setRuleEnabled(entry, enabled: value) } })
        ).toggleStyle(.switch).controlSize(.small).labelsHidden()
        Menu {
          Button(L10n.text("intents.edit")) { editing = RuleDraft(editing: entry) }
          Divider()
          Button(L10n.text("common.delete"), role: .destructive) { deleting = entry }
        } label: {
          NativeIcon(name: "DotsVerticalIcon", size: 16)
        }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden)
      }
      HStack(spacing: 6) {
        Text(L10n.text("cond.conditionText", ["prefix": entry.rule.prefix]))
        if let interface = status.matchedInterface {
          Text(L10n.text("cond.onIface", ["iface": interface])).foregroundStyle(p["up"])
        }
      }.font(.system(size: 11.2)).foregroundStyle(p.secondary)
      Text(entry.rule.routes.map(\.text).joined(separator: "   "))
        .font(.system(size: 11.2, design: .monospaced)).foregroundStyle(p.secondary)
        .textSelection(.enabled)
      Text(status.detail ?? L10n.text(status.state.hint)).font(.system(size: 10.92))
        .foregroundStyle(status.state == .error ? p["down"] : p.muted)
    }
    .padding(.horizontal, 8).padding(.vertical, 9)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }
}

private struct RuleDraftBox: Identifiable {
  let draft: RuleDraft
  var id: String { draft.editing ? "edit-" + draft.id : "new" }
}

private struct RuleSheet: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State var draft: RuleDraft
  let onClose: () -> Void
  @State private var saving = false

  var body: some View {
    AppModal(
      title: draft.editing ? "cond.editTitle" : "cond.newTitle", width: 520, onClose: onClose
    ) {
      VStack(alignment: .leading, spacing: 12) {
        field("cond.name") { AppInput(placeholder: "cond.namePh", text: $draft.name) }
        field("cond.id") {
          AppInput(placeholder: "cond.idPh", text: $draft.id).disabled(draft.editing)
        }
        field("cond.condPrefix") { AppInput(placeholder: "10.228.32.0/21", text: $draft.prefix) }
        field("cond.routesWhile") {
          TextEditor(text: $draft.routes)
            .font(.system(size: 11.9, design: .monospaced)).scrollContentBackground(.hidden)
            .frame(height: 84).padding(6).background(p.input, in: RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
          Text(L10n.text("native.rules.routesHint")).font(.system(size: 10.92)).foregroundStyle(
            p.muted)
        }
        Toggle(L10n.text("cond.enabled"), isOn: $draft.enabled).toggleStyle(.switch)
          .controlSize(.small)
        HStack {
          Spacer()
          Button(L10n.text("common.cancel"), action: onClose)
          Button(L10n.text("common.save")) { Task { await save() } }
            .buttonStyle(TauriButtonStyle(kind: .accent))
            .disabled(!draft.isComplete || saving)
        }
      }.padding(14)
    }
  }

  private func field<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content)
    -> some View
  {
    VStack(alignment: .leading, spacing: 5) {
      Text(L10n.text(title)).font(.system(size: 11.2, weight: .medium)).foregroundStyle(p.secondary)
      content()
    }
  }

  private func save() async {
    saving = true
    defer { saving = false }
    if await model.saveRule(draft) { onClose() }
  }
}
