import SwiftUI

/// "These networks go this way": rules the privileged helper installs, keeps
/// and puts back, waiting while a device they name is absent.
struct IntentsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var editing: IntentDraft?

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack {
        Text(L10n.text("intents.hint")).font(.system(size: 11.9)).foregroundStyle(p.secondary)
        Spacer(minLength: 12)
        Button(L10n.text("intents.add")) { editing = IntentDraft() }
          .buttonStyle(TauriButtonStyle(kind: .accent)).disabled(!model.canUseIntents)
      }
      if !model.canUseIntents {
        AppEmptyState { Text(L10n.text("native.intents.needsHelper")) }
      } else if model.intents.isEmpty {
        AppEmptyState { Text(L10n.text("intents.empty")) }
      } else {
        VStack(alignment: .leading, spacing: 0) {
          ForEach(model.intents) { intent in row(intent) }
        }
      }
    }
    // The helper keeps reconciling; the page follows it while it is open.
    .task {
      while !Task.isCancelled {
        await model.loadIntents()
        try? await Task.sleep(for: .seconds(3))
      }
    }
    .sheet(item: Binding(get: { editing.map(DraftBox.init) }, set: { editing = $0?.draft })) { box in
      IntentSheet(model: model, draft: box.draft) { editing = nil }
        .environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
  }

  private func row(_ intent: RouteIntent) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      HStack(spacing: 8) {
        Text(intent.id).font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        AppBadge(text: intent.status.label, color: intent.status.badgeColor)
        Text(intent.isDirect ? L10n.text("intents.pathDirect") : intent.pathText)
          .font(.system(size: 11.2, design: intent.isDirect ? .default : .monospaced))
          .foregroundStyle(p.secondary).lineLimit(1)
        Spacer(minLength: 12)
        if intent.wanted > 0 {
          Text(
            L10n.text(
              "native.intents.routes",
              ["installed": String(intent.installed), "wanted": String(intent.wanted)])
          ).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
        Toggle(
          "",
          isOn: Binding(
            get: { intent.enabled },
            set: { value in Task { await model.setIntentEnabled(intent, enabled: value) } })
        ).toggleStyle(.switch).controlSize(.small).labelsHidden()
        Menu {
          Button(L10n.text("intents.edit")) { editing = IntentDraft(editing: intent) }
          Divider()
          Button(L10n.text("common.delete"), role: .destructive) {
            Task { await model.deleteIntent(intent) }
          }
        } label: {
          NativeIcon(name: "DotsVerticalIcon", size: 16)
        }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden)
      }
      Text(intent.destinations.joined(separator: "   "))
        .font(.system(size: 11.2, design: .monospaced)).foregroundStyle(p.secondary)
        .textSelection(.enabled)
      Text(intent.detail).font(.system(size: 10.92)).foregroundStyle(
        intent.status == .conflicted ? p["down"] : p.muted)
      if RouteIntent.capturesDefault(intent.destinations) {
        Text(L10n.text("native.intents.captureDefault")).font(.system(size: 10.92))
          .foregroundStyle(p["warn"])
      }
    }
    .padding(.horizontal, 8).padding(.vertical, 9)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }
}

/// `sheet(item:)` needs an identifiable value.
private struct DraftBox: Identifiable {
  let draft: IntentDraft
  var id: String { draft.editing ? "edit-" + draft.id : "new" }
}

private struct IntentSheet: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State var draft: IntentDraft
  let onClose: () -> Void
  @State private var saving = false

  private var devices: [String] {
    (model.snapshot?.interfaces ?? []).map(\.name).filter { $0 != "lo0" }
  }

  var body: some View {
    AppModal(
      title: draft.editing ? "intents.editTitle" : "intents.addTitle", width: 520, onClose: onClose
    ) {
      VStack(alignment: .leading, spacing: 12) {
        field("intents.fieldId") {
          AppInput(placeholder: "intents.fieldIdPlaceholder", text: $draft.id)
            .disabled(draft.editing)
        }
        field("intents.fieldDestinations") {
          TextEditor(text: $draft.destinations)
            .font(.system(size: 11.9, design: .monospaced)).scrollContentBackground(.hidden)
            .frame(height: 76).padding(6).background(p.input, in: RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
        }
        field("intents.colPath") {
          Picker("", selection: $draft.useInterface) {
            Text(L10n.text("intents.pathDirect")).tag(false)
            Text(L10n.text("native.intents.viaInterface")).tag(true)
          }.labelsHidden().pickerStyle(.segmented)
          if draft.useInterface {
            HStack(spacing: 7) {
              AppInput(placeholder: "native.intents.interface", text: $draft.interface)
              Menu(L10n.text("native.intents.interface")) {
                ForEach(devices, id: \.self) { name in
                  Button(name) { draft.interface = name }
                }
              }.menuStyle(.button).fixedSize()
            }
          }
        }
        Toggle(L10n.text("intents.enable"), isOn: $draft.enabled).toggleStyle(.switch)
          .controlSize(.small)
        if RouteIntent.capturesDefault(
          draft.destinations.split(whereSeparator: { ",; \n\t".contains($0) }).map(String.init))
        {
          Text(L10n.text("native.intents.captureDefault")).font(.system(size: 11.2))
            .foregroundStyle(p["warn"])
        }
        Text(L10n.text("intents.formHint")).font(.system(size: 10.92)).foregroundStyle(p.muted)
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
    if await model.saveIntent(draft) { onClose() }
  }
}
